package org.kotlintor.dir

/**
 * Hard-coded default directory authorities (from Tor's dirauth list; verify against
 * https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/auth_dirs.inc
 * when updating).
 */
data class DirectoryAuthority(
    val nickname: String,
    val address: String,
    val dirPort: Int,
    val orPort: Int,
    val v3Ident: String,
)

object DefaultAuthorities {
    val ALL: List<DirectoryAuthority> = listOf(
        DirectoryAuthority("moria1", "128.31.0.39", 9131, 9101, "F533C81CEF0BC161345A76E3A3E7F5D8F8211B5C"),
        DirectoryAuthority("tor26", "217.13.201.192", 80, 443, "2F3DF9CA0E5D36F2685A2DA67184EB6EAACADE9E"),
        DirectoryAuthority("dizum", "45.66.35.11", 80, 443, "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"),
        DirectoryAuthority("gabelmoo", "131.188.40.189", 80, 443, "ED03BB616EB2F60BEC80151114BB25CEF515B226"),
        DirectoryAuthority("dannenberg", "193.23.244.244", 80, 443, "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"),
        DirectoryAuthority("maatuska", "171.25.193.9", 443, 80, "49015F787433103580E3B66A1707A00E60F2D15B"),
        DirectoryAuthority("longclaw", "199.58.81.140", 80, 443, "74A910646BCEEFBCD2E874FC1DC997430F968145"),
        DirectoryAuthority("bastet", "204.13.164.118", 80, 443, "27102BC123E7AF1D4741AE047E160C91ADB76A8E"),
        DirectoryAuthority("faravahar", "216.218.219.41", 80, 443, "EFCBE720AB3A82B99F9E953CD5BF50F7DABC5F26"),
    )
}
