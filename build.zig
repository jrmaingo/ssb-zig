const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("ssb", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();
    exe.addIncludeDir("/usr/local/include/sodium/");
    exe.linkSystemLibrary("sodium");

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest("src/main.zig");
    tests.setBuildMode(.Debug);
    tests.addIncludeDir("/usr/local/include/sodium/");
    tests.linkSystemLibrary("sodium");

    const test_step = b.step("test", "Run the tests");
    test_step.dependOn(&tests.step);
}
