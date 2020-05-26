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

    std.debug.warn("pk: {}\nsk: {}\nres: {}\n", .{ identity.pk, identity.sk, c_res });

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
fn saveIdentity(ssb_path: []const u8, identity: Identity) !void {
    const cwd = std.fs.cwd();

    // Dir.makeOpenPath not visible for some reason :(
    std.debug.warn("ssb_path: {}\n", .{ssb_path});
    try cwd.makeDir(ssb_path);
    var ssb_dir = try cwd.openDir(ssb_path, .{});
    defer ssb_dir.close();

    const create_flags = std.fs.File.CreateFlags{
        .exclusive = true,
    };
    const secret_file = try ssb_dir.createFile(secret_file_name, create_flags);
    defer secret_file.close();

    // TODO write key to file
    @panic("Unimplemented");
}

// try to load identity from ${HOME}/.ssb
fn loadIdentity(ssb_path: []const u8) !Identity {
    const ssb_dir = try std.fs.cwd().openDir(ssb_path, .{});
    const secret_file = try ssb_dir.openFile(secret_file_name, .{});
    defer secret_file.close();

    // TODO read identity from file
    @panic("Unimplemented");
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

    const identity = loadIdentity(ssb_path) catch |err| loadErr: {
        // TODO check error cases

        // gen new Identity and write to file
        const newIdentity = makeIdenity();
        try saveIdentity(ssb_path, newIdentity);
        break :loadErr newIdentity;
    };

    std.debug.warn("secret saved to {}\n", .{ssb_path});
}
