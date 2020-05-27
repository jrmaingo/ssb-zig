const c = @cImport(@cInclude("sodium.h"));
const std = @import("std");

const ssb_dir_name = ".ssb";
const secret_file_name = "secret";

const CryptoError = error{GenerationFailure};

const Identity = struct {
    pk: [c.crypto_sign_ed25519_PUBLICKEYBYTES]u8 = [_]u8{0} ** c.crypto_sign_ed25519_PUBLICKEYBYTES,
    sk: [c.crypto_sign_ed25519_SECRETKEYBYTES]u8 = [_]u8{0} ** c.crypto_sign_ed25519_SECRETKEYBYTES,
    feed_id: [feed_id_len]u8 = [_]u8{0} ** feed_id_len,

    const feed_id_prefix = "@";
    const feed_id_suffix = ".ed25519";
    const feed_id_len = feed_id_prefix.len + std.base64.Base64Encoder.calcSize(c.crypto_sign_ed25519_PUBLICKEYBYTES) + feed_id_suffix.len;

    fn getFeedID(pk: [c.crypto_sign_ed25519_PUBLICKEYBYTES]u8, feed_id: []u8) void {
        var pk_base64 = [_]u8{0} ** std.base64.Base64Encoder.calcSize(pk.len);
        std.base64.standard_encoder.encode(&pk_base64, &pk);
        const feed_id_parts = [_][]const u8{ Identity.feed_id_prefix, &pk_base64, Identity.feed_id_suffix };

        const out_stream = std.io.fixedBufferStream(feed_id).outStream();
        for (feed_id_parts) |part| {
            std.debug.warn("part: {}\n", .{part});
            out_stream.writeAll(part) catch unreachable;
            // TODO handle out buf of wrong size
        }

        std.debug.warn("feed_id: {}\n", .{feed_id});
    }

    fn createWithKeypair(sk: [c.crypto_sign_ed25519_SECRETKEYBYTES]u8, pk: [c.crypto_sign_ed25519_PUBLICKEYBYTES]u8) Identity {
        var identity = Identity{};

        std.mem.copy(u8, &identity.sk, &sk);
        std.mem.copy(u8, &identity.pk, &pk);

        Identity.getFeedID(identity.pk, &identity.feed_id);

        std.debug.warn("{x}\n", .{identity});

        return identity;
    }

    // gen a new identity keypair with libsodium
    fn create() !Identity {
        var identity = Identity{};

        // generate identity key pair
        const c_res = c.crypto_sign_ed25519_keypair(&identity.pk, &identity.sk);
        if (c_res != 0) {
            return CryptoError.GenerationFailure;
        }

        Identity.getFeedID(identity.pk, &identity.feed_id);

        std.debug.warn("created keypair:\n{x}\n", .{identity});

        return identity;
    }

    fn createFromSecretKey(sk: [c.crypto_sign_ed25519_SECRETKEYBYTES]u8) !Identity {
        var pk: [c.crypto_sign_ed25519_PUBLICKEYBYTES]u8 = undefined;
        const c_res = c.crypto_sign_ed25519_sk_to_pk(&pk, &sk);
        if (c_res != 0) {
            // TODO raise error
            @panic("Unimplemented");
        }

        var identity = Identity.createWithKeypair(sk, pk);

        Identity.getFeedID(identity.pk, &identity.feed_id);

        std.debug.warn("loaded keypair:\n{x}\n", .{identity});

        return identity;
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

// save a newly generated identity to ${HOME}/.ssb/secret
fn saveIdentity(ssb_dir: std.fs.Dir, identity: Identity) !void {
    const create_flags = std.fs.File.CreateFlags{
        .exclusive = true,
    };
    const secret_file = try ssb_dir.createFile(secret_file_name, create_flags);
    defer secret_file.close();

    try secret_file.writeAll(&identity.sk);

    std.debug.warn("done writing\n", .{});
}

// try to load identity from ${HOME}/.ssb
fn loadIdentity(ssb_dir: std.fs.Dir) !Identity {
    const secret_file = try ssb_dir.openFile(secret_file_name, .{});
    defer secret_file.close();

    var sk: [c.crypto_sign_ed25519_SECRETKEYBYTES]u8 = undefined;

    const read_len = try secret_file.readAll(&sk);
    if (read_len != sk.len) {
        // TODO raise error
        @panic("Unimplemented");
    }

    return try Identity.createFromSecretKey(sk);
}

pub fn main() anyerror!void {
    const allocator = std.heap.c_allocator;

    var c_res = c.sodium_init();
    if (c_res != 0) {
        std.debug.warn("sodium init error\n", .{});
        // TODO return error
        @panic("Unimplemented");
    }

    const ssb_path = try getSsbPath(allocator);
    defer allocator.free(ssb_path);

    // open ssb dir, create if needed
    var ssb_dir = std.fs.cwd().openDir(ssb_path, .{}) catch |err| switch (err) {
        error.FileNotFound => notFound: {
            try std.fs.cwd().makeDir(ssb_path);
            break :notFound try std.fs.cwd().openDir(ssb_path, .{});
        },
        else => unreachable,
    };
    defer ssb_dir.close();

    // load identity, create if needed
    const identity = loadIdentity(ssb_dir) catch |err| loadErr: {
        // TODO check error cases

        // gen new Identity and write to file
        const newIdentity = try Identity.create();
        try saveIdentity(ssb_dir, newIdentity);
        break :loadErr newIdentity;
    };
}
