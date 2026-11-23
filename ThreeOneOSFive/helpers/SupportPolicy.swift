import Foundation

enum ExploitSupportPolicy {
    // Kernel / 3105 offset table (offsets.m): 17.0 – 18.7.x and 26.0.x
    static let verifiedIOS17Range = "17.0–17.7.x"
    static let verifiedIOS18Range = "18.0–18.7.x"
    static let verifiedIOS26KernelRange = "26.0.x"

    // worse_query (App Group sandbox extension): 26.0 – 26.7.2 + 27.0 – 27.2.1 + 27.3 Beta1 24C5037i
    static let verifiedIOS26WorseQueryRange = "26.0–26.7.2"
    static let verifiedIOS27WorseQueryRange = "27.0–27.2.1 + 27.3b1 (24C5037i)"

    // Legacy 27 developer betas that still use the old kernel policy display
    static let verifiedIOS27Builds: [(beta: Int, publicBeta: Int?, build: String)] = [
        (1, nil, "24A5355q"),
        (2, nil, "24A5370h"),
        (3, 1, "24A5380h"),
        (4, 2, "24A5390f")
    ]

    // Exact build required for 27.3 beta 1 (worse_query)
    static let verifiedIOS27Beta1Build = "24C5037i"

    static func iOS27BetaNumber(for build: String) -> Int? {
        verifiedIOS27Builds.first { $0.build == build }?.beta
    }

    static func iOS27PublicBetaNumber(for build: String) -> Int? {
        verifiedIOS27Builds.first { $0.build == build }?.publicBeta
    }

    /// Kernel exploit path (offsets.m + kexploit_opa334). Stock devices.
    static func supportsKernelExploit(major: Int, minor: Int, patch: Int) -> Bool {
        guard minor >= 0, patch >= 0 else { return false }

        if major == 17 {
            return minor <= 7
        }
        if major == 18 {
            return minor <= 7
        }
        // offsets.m hard-gates to < 26.1
        if major == 26 {
            return minor == 0
        }
        return false
    }

    /// worse_query path (App Group + container grant). Requires provisioned group.
    static func supportsWorseQuery(major: Int, minor: Int, patch: Int, build: String) -> Bool {
        guard minor >= 0, patch >= 0 else { return false }

        if major == 26 {
            return minor < 7 || (minor == 7 && patch <= 2)
        }
        if major != 27 {
            return false
        }
        if minor < 2 {
            return true
        }
        if minor == 2 {
            return patch <= 1
        }
        // 27.3 only exact beta 1 build
        return minor == 3 && patch == 0 && build == verifiedIOS27Beta1Build
    }

    /// Jailbreak unsandboxed path (15/16 and any version when /var/jb etc is present).
    static func supportsJailbreakPath(major: Int) -> Bool {
        return major >= 15
    }

    /// Any backend that can give real container / file access on this OS.
    static func isSupported(major: Int, minor: Int, patch: Int, build: String) -> Bool {
        if supportsKernelExploit(major: major, minor: minor, patch: patch) {
            return true
        }
        if supportsWorseQuery(major: major, minor: minor, patch: patch, build: build) {
            return true
        }
        // 15/16 always report as supported when jailbreak path is available at runtime.
        // Launch is never blocked; only the action is gated.
        if major == 15 || major == 16 {
            return true
        }
        return false
    }

    /// Human label for Settings / status.
    static func backendLabel(major: Int, minor: Int, patch: Int, build: String) -> String {
        if supportsWorseQuery(major: major, minor: minor, patch: patch, build: build) {
            return "worse_query"
        }
        if supportsKernelExploit(major: major, minor: minor, patch: patch) {
            return "kernel (3105)"
        }
        if major == 15 || major == 16 {
            return "jailbreak path"
        }
        return "unsupported"
    }
}
