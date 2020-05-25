const c = @cImport(@cInclude("sodium.h"));
const std = @import("std");
const allocator = std.heap.c_allocator;

pub fn main() anyerror!void {
    var c_res = c.sodium_init();
    if (c_res != 0) {
        std.debug.warn("sodium init error\n", .{});
        // TODO return error
    }

    var pk = [_]u8{0} ** c.crypto_sign_ed25519_PUBLICKEYBYTES;
    var sk = [_]u8{0} ** c.crypto_sign_ed25519_SECRETKEYBYTES;

    // generate identity key pair
    c_res = c.crypto_sign_ed25519_keypair(&pk, &sk);
    if (c_res != 0) {
        // TODO return error
    }

    std.debug.warn("pk: {}\nsk: {}\nres: {}\n", .{ pk, sk, c_res });

    // save key to file
    const secret_path = if (std.os.getenv("HOME")) |home_dir|
        try std.fs.path.join(allocator, &[_][]const u8{ home_dir, ".ssb" })
    else
        unreachable;
    defer allocator.free(secret_path);

    std.debug.warn("secret saved to {}\n", .{secret_path});
}
