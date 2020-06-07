const sodium = @cImport(@cInclude("sodium.h"));
const ifaddrs = @cImport(@cInclude("ifaddrs.h"));
const c = std.c;
const std = @import("std");
const warn = std.debug.warn;
const net = std.net;

const ssb_dir_name = ".ssb";
const secret_file_name = "secret";

const CryptoError = error{ Unknown, KeyGenFail, BadKeyFormat };

const Identity = struct {
    pk: [sodium.crypto_sign_ed25519_PUBLICKEYBYTES]u8 = [_]u8{0} ** sodium.crypto_sign_ed25519_PUBLICKEYBYTES,
    sk: [sodium.crypto_sign_ed25519_SECRETKEYBYTES]u8 = [_]u8{0} ** sodium.crypto_sign_ed25519_SECRETKEYBYTES,
    feed_id: [feed_id_len]u8 = [_]u8{0} ** feed_id_len,

    const feed_id_prefix = "@";
    const feed_id_suffix = ".ed25519";
    const feed_id_len = feed_id_prefix.len + std.base64.Base64Encoder.calcSize(sodium.crypto_sign_ed25519_PUBLICKEYBYTES) + feed_id_suffix.len;

    fn getFeedID(pk: [sodium.crypto_sign_ed25519_PUBLICKEYBYTES]u8, feed_id: []u8) !void {
        var pk_base64 = [_]u8{0} ** std.base64.Base64Encoder.calcSize(pk.len);

        if (feed_id.len < pk_base64.len) {
            return error.NoSpaceLeft;
        }

        std.base64.standard_encoder.encode(&pk_base64, &pk);
        const feed_id_parts = [_][]const u8{ Identity.feed_id_prefix, &pk_base64, Identity.feed_id_suffix };

        const out_stream = std.io.fixedBufferStream(feed_id).outStream();
        for (feed_id_parts) |part| {
            out_stream.writeAll(part) catch unreachable;
        }

        warn("feed_id: {}\n", .{feed_id});
    }

    fn createWithKeypair(sk: [sodium.crypto_sign_ed25519_SECRETKEYBYTES]u8, pk: [sodium.crypto_sign_ed25519_PUBLICKEYBYTES]u8) !Identity {
        var identity = Identity{};

        std.mem.copy(u8, &identity.sk, &sk);
        std.mem.copy(u8, &identity.pk, &pk);

        try Identity.getFeedID(identity.pk, &identity.feed_id);

        warn("{x}\n", .{identity});

        return identity;
    }

    // gen a new identity keypair with libsodium
    fn create() !Identity {
        var sk: [sodium.crypto_sign_ed25519_SECRETKEYBYTES]u8 = undefined;
        var pk: [sodium.crypto_sign_ed25519_PUBLICKEYBYTES]u8 = undefined;

        // generate identity key pair
        const c_res = sodium.crypto_sign_ed25519_keypair(&pk, &sk);
        if (c_res != 0) {
            return CryptoError.KeyGenFail;
        }

        return try Identity.createWithKeypair(sk, pk);
    }

    fn createFromSecretKey(sk: [sodium.crypto_sign_ed25519_SECRETKEYBYTES]u8) !Identity {
        var pk: [sodium.crypto_sign_ed25519_PUBLICKEYBYTES]u8 = undefined;

        // derive pk from sk
        const c_res = sodium.crypto_sign_ed25519_sk_to_pk(&pk, &sk);
        if (c_res != 0) {
            return error.KeyGenFail;
        }

        return try Identity.createWithKeypair(sk, pk);
    }
};

// caller frees return buf
// using defer allocator.free(ssb_path);
fn getSsbPath(allocator: *std.mem.Allocator) ![]u8 {
    return if (std.os.getenv("HOME")) |home_dir|
        try std.fs.path.join(allocator, &[_][]const u8{ home_dir, ssb_dir_name })
    else
        unreachable;
}

// TODO store with a sig to detect corruption?
// save a newly generated identity to ${HOME}/.ssb/secret
fn saveIdentity(ssb_dir: std.fs.Dir, identity: Identity) !void {
    errdefer warn("failed to write identity to file...\n", .{});

    const create_flags = std.fs.File.CreateFlags{
        .exclusive = true,
    };
    const secret_file = try ssb_dir.createFile(secret_file_name, create_flags);
    defer secret_file.close();

    try secret_file.writeAll(&identity.sk);

    warn("done writing\n", .{});
}

// try to load identity from ${HOME}/.ssb
fn loadIdentity(ssb_dir: std.fs.Dir) !Identity {
    errdefer warn("failed to load identity...\n", .{});

    const secret_file = try ssb_dir.openFile(secret_file_name, .{});
    defer secret_file.close();

    var sk: [sodium.crypto_sign_ed25519_SECRETKEYBYTES]u8 = undefined;

    const read_len = try secret_file.readAll(&sk);
    if (read_len != sk.len) {
        return error.BadKeyFormat;
    }

    if (Identity.createFromSecretKey(sk)) |newIdentity| {
        warn("successfully loaded identity\n", .{});
        return newIdentity;
    } else |err| return err;
}

fn getAddr() !net.Address {
    // get list of interfaces
    var my_ifaddrs: [*c]ifaddrs.ifaddrs = null;
    const ifaddrs_result = ifaddrs.getifaddrs(&my_ifaddrs);
    if (ifaddrs_result == -1) {
        warn("errno: {}\n", .{c.getErrno(ifaddrs_result)});
        return error.NoInterfaceAddress;
    }
    defer ifaddrs.freeifaddrs(my_ifaddrs);

    // pick the first usable IPv4 interface
    var cur_ifaddr = my_ifaddrs;
    return while (cur_ifaddr != null) : (cur_ifaddr = cur_ifaddr.*.ifa_next) {
        const sockaddr = @ptrCast(*std.os.sockaddr, cur_ifaddr.*.ifa_addr);
        if (sockaddr.*.family == c.AF_INET) {
            const name = @as([*:0]const u8, cur_ifaddr.*.ifa_name);
            const addr = net.Address{ .in = @ptrCast(*std.os.sockaddr_in, @alignCast(4, sockaddr)).* };
            warn("name: {}, addr: {}\n", .{ name, addr });
            if (!std.mem.eql(u8, name[0..2], "lo")) {
                // choose first non-loopback interface
                warn("chose: {}\n", .{name});
                break addr;
            }
        }
    } else error.NoInterfaceAddress;
}

pub fn main() anyerror!void {
    const allocator = std.heap.c_allocator;

    var c_res = sodium.sodium_init();
    if (c_res != 0) {
        warn("sodium init error\n", .{});
        return CryptoError.Unknown;
    }

    const ssb_path = try getSsbPath(allocator);
    defer allocator.free(ssb_path);

    // open ssb dir, create if needed
    var ssb_dir = std.fs.cwd().openDir(ssb_path, .{}) catch |err| switch (err) {
        error.FileNotFound => notFound: {
            try std.fs.cwd().makeDir(ssb_path);
            break :notFound try std.fs.cwd().openDir(ssb_path, .{});
        },
        else => return err,
    };
    defer ssb_dir.close();

    // load identity, create if needed
    const identity = loadIdentity(ssb_dir) catch |err| switch (err) {
        error.KeyGenFail, error.FileNotFound, error.BadKeyFormat => noIdentity: {
            // gen new Identity and write to file
            const newIdentity = try Identity.create();
            try saveIdentity(ssb_dir, newIdentity);
            break :noIdentity newIdentity;
        },
        else => return err,
    };

    const self_addr = try getAddr();

    // TODO create advertising pkt for self
    const ad_pkt = "TODO actual pk";

    // open socket
    const socket = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
    if (socket == -1) {
        warn("errno: {}\n", .{c.getErrno(socket)});
        return error.NoSocket;
    }

    // advertise self locally
    const flags = 0; // TODO
    //"255.255.255.255",
    const addr = try net.Address.parseIp("127.0.0.1", 8008);
    var send_result = c.sendto(socket, ad_pkt, ad_pkt.len, flags, &addr.any, addr.any.len);
    if (send_result == -1) {
        warn("errno: {}\n", .{c.getErrno(send_result)});
        return error.SendFail;
    }

    // TODO rest of program
}
