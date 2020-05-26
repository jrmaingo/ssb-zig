const c = @cImport(@cInclude("sodium.h"));
const std = @import("std");

const ssb_dir_name = ".ssb";
const secret_file_name = "secret";

const Identity = packed struct {
    pk: [c.crypto_sign_ed25519_PUBLICKEYBYTES]u8 = [_]u8{0} ** c.crypto_sign_ed25519_PUBLICKEYBYTES,
    sk: [c.crypto_sign_ed25519_SECRETKEYBYTES]u8 = [_]u8{0} ** c.crypto_sign_ed25519_SECRETKEYBYTES,
};

// gen a new identity keypair with libsodium
fn makeIdenity() Identity {
    var identity = Identity{};

    // generate identity key pair
    const c_res = c.crypto_sign_ed25519_keypair(&identity.pk, &identity.sk);
    if (c_res != 0) {
        // TODO return error
        @panic("Unimplemented");
    }

    std.debug.warn("pk: {x}\nsk: {x}\nres: {}\n", .{ identity.pk, identity.sk, c_res });

    return identity;
}

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

    var identity = Identity{};

    const read_len = try secret_file.readAll(&identity.sk);
    if (read_len != identity.sk.len) {
        // TODO raise error
        @panic("Unimplemented");
    }

    const c_res = c.crypto_sign_ed25519_sk_to_pk(&identity.pk, &identity.sk);
    if (c_res != 0) {
        // TODO raise error
        @panic("Unimplemented");
    }

    std.debug.warn("loaded keypair:\npk: {x}\nsk: {x}\nres: {}\n", .{ identity.pk, identity.sk, c_res });

    return identity;
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
        const newIdentity = makeIdenity();
        try saveIdentity(ssb_dir, newIdentity);
        break :loadErr newIdentity;
    };
}
