#!/usr/bin/env node
/**
 * Regression test: verify postcss version >= 8.5.11 (CVE-2026-41305).
 *
 * Usage: node scripts/verify-postcss-version.js
 * Exit: 0 if all postcss instances are patched, 1 otherwise.
 */

const { execSync } = require('child_process');

function getPostcssVersions() {
    try {
        const stdout = execSync('npm ls postcss --legacy-peer-deps', {
            cwd: __dirname + '/..',
            encoding: 'utf-8',
        });
        return stdout;
    } catch (e) {
        return e.stdout || '';
    }
}

function main() {
    const tree = getPostcssVersions();
    // Match lines that show postcss as a dependency, not postcss-* or @*/postcss.
    // We look for lines that end with "postcss@X.X.X" (not postcss-* or @something/postcss).
    const lines = tree.split('\n');
    const versions = [];
    for (const line of lines) {
        // Match: postcss@X.X.X at end of line (possibly with trailing words like "deduped")
        const m = line.match(/postcss@(\d+\.\d+\.\d+(?:-[\w.]+)?)\b/);
        if (m) {
            // Exclude false matches like @tailwindcss/postcss (version matched is postcss@4.2.2 from @tailwindcss/postcss@4.2.2)
            // "@tailwindcss/postcss@4.2.2" → regex would match postcss@4.2.2 but that's wrong.
            // The real postcss version is in dependency lines, not in the package name itself.
            // Skip lines where "postcss@" is preceded by a name that includes a slash (e.g., @tailwindcss/postcss)
            const idx = line.indexOf('postcss@');
            const before = line.substring(0, idx).trim();
            // If before ends with a slash or starts with @ after the last alnum, it's a scoped package name
            if (before.includes('/')) {
                // @tailwindcss/postcss - skip, this is not the postcss package
                continue;
            }
            versions.push(m[1]);
        }
    }

    if (versions.length === 0) {
        console.error('No postcss versions found in dependency tree.');
        process.exit(1);
    }

    const target = [8, 5, 11];
    let ok = true;
    for (const v of versions) {
        const [maj, min, patchStr] = v.split('.');
        const patch = parseInt(patchStr.split('-')[0], 10);
        const current = [parseInt(maj, 10), parseInt(min, 10), patch];
        const isPatched =
            current[0] > target[0] ||
            (current[0] === target[0] && current[1] > target[1]) ||
            (current[0] === target[0] && current[1] === target[1] && current[2] >= target[2]);
        if (!isPatched) {
            console.error(`FAIL: postcss@${v} is below patched version 8.5.11 (CVE-2026-41393)`);
            ok = false;
        } else {
            console.log(`PASS: postcss@${v} >= 8.5.11`);
        }
    }

    if (!ok) {
        process.exit(1);
    }
    console.log('All postcss versions are patched. No CVE-2026-41305 exposure.');
    process.exit(0);
}

main();
