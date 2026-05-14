// build.rs
//
// Automatically wires up the WinDivert SDK that ships in the
// WinDivert-2.2.2-A/ subfolder of this project:
//
//   • Embeds a Windows application manifest requesting Administrator execution
//     level — Windows shows the UAC shield and elevation prompt on launch.
//   • Adds the correct x64/ or x86/ subfolder to the native library search
//     path so the linker can find WinDivert.lib.
//   • Copies WinDivert.dll and WinDivert*.sys to the Cargo output directory
//     (target/{debug|release}/) so argus.exe finds the driver at runtime.

use std::path::PathBuf;

fn main() {
    // ── UAC manifest (Windows only) ─────────────────────────────────────────
    // Embedding requestedExecutionLevel = requireAdministrator causes:
    //   • Windows Explorer to show the UAC shield icon on argus.exe
    //   • An automatic UAC elevation prompt when the user double-clicks it
    //     or runs it from an unelevated terminal
    #[cfg(target_os = "windows")]
    {
        use embed_manifest::{embed_manifest, new_manifest};
        use embed_manifest::manifest::ExecutionLevel;
        embed_manifest(
            new_manifest("Argus")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("Failed to embed UAC manifest into argus.exe");
        println!("cargo:rerun-if-changed=build.rs");
    }
    // ── Architecture ────────────────────────────────────────────────────────
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let arch_dir = match arch.as_str() {
        "x86_64" => "x64",
        "x86"    => "x86",
        other    => panic!("Unsupported target architecture for WinDivert: {other}"),
    };

    // ── Paths ────────────────────────────────────────────────────────────────
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    );
    let sdk_dir = manifest_dir.join("WinDivert-2.2.2-A").join(arch_dir);

    assert!(
        sdk_dir.exists(),
        "WinDivert SDK folder not found: {}",
        sdk_dir.display()
    );

    // ── Linker search path (compile-time) ───────────────────────────────────
    println!("cargo:rustc-link-search=native={}", sdk_dir.display());

    // Re-run build.rs if the SDK folder changes.
    println!("cargo:rerun-if-changed=WinDivert-2.2.2-A");

    // ── Copy runtime files to target/{profile}/ ─────────────────────────────
    // OUT_DIR is target/{profile}/build/{crate}-{hash}/out — go up 3 levels.
    let out_dir = PathBuf::from(
        std::env::var("OUT_DIR").expect("OUT_DIR not set"),
    );
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("Unexpected OUT_DIR depth")
        .to_path_buf();

    let sys_file = if arch_dir == "x64" {
        "WinDivert64.sys"
    } else {
        "WinDivert32.sys"
    };

    for filename in &["WinDivert.dll", sys_file] {
        let src = sdk_dir.join(filename);
        let dst = profile_dir.join(filename);

        if src.exists() {
            match std::fs::copy(&src, &dst) {
                Ok(_)  => println!("cargo:warning=Copied {filename} → {}", profile_dir.display()),
                Err(e) => println!("cargo:warning=Could not copy {filename}: {e}"),
            }
        } else {
            println!("cargo:warning=WinDivert file not found: {}", src.display());
        }
    }
}
