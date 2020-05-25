const c = @cImport(@cInclude("sodium.h"));
const std = @import("std");

pub fn main() anyerror!void {
    var c_res = c.sodium_init();
    if (c_res != 0) {
        std.debug.warn("sodium init error\n", .{});
    }

    var pk: [c.crypto_box_PUBLICKEYBYTES]u8 = undefined;
    var sk: [c.crypto_box_SECRETKEYBYTES]u8 = undefined;

    c_res = c.crypto_box_keypair(&pk, &sk);

    std.debug.warn("pk: {}\nsk: {}\nres: {}\n", .{ pk, sk, c_res });
}
