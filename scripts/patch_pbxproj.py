#!/usr/bin/env python3
"""Patching zeroxjf Xcode project to add exploit source files"""
import sys, uuid, re

PROJECT = sys.argv[1] if len(sys.argv) > 1 else 'base/ios-app/Test.xcodeproj/project.pbxproj'

with open(PROJECT, 'r') as f:
    content = f.read()

# Generate unique IDs
def gen_id(): return uuid.uuid4().hex[:24].upper()

ids = {
    'krw_h': gen_id(),
    'krw_m': gen_id(),
    'krw_build': gen_id(),
    'coll_h': gen_id(),
    'coll_m': gen_id(),
    'coll_build': gen_id(),
}

# 1. Add file references
refs = f"""\
\t\t{ids['krw_m']} /* applejpeg_krw.m */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = applejpeg_krw.m; sourceTree = "<group>"; }};
\t\t{ids['krw_h']} /* applejpeg_krw.h */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; path = applejpeg_krw.h; sourceTree = "<group>"; }};
\t\t{ids['coll_m']} /* collector.m */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = collector.m; sourceTree = "<group>"; }};
\t\t{ids['coll_h']} /* collector.h */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; path = collector.h; sourceTree = "<group>"; }};"""
content = content.replace('/* End PBXFileReference section */',
                          refs + '\n/* End PBXFileReference section */')

# 2. Add build file references
build = f"""\
\t\t{ids['krw_build']} /* applejpeg_krw.m in Sources */ = {{isa = PBXBuildFile; fileRef = {ids['krw_m']} /* applejpeg_krw.m */; }};
\t\t{ids['coll_build']} /* collector.m in Sources */ = {{isa = PBXBuildFile; fileRef = {ids['coll_m']} /* collector.m */; }};"""
content = content.replace('/* End PBXBuildFile section */',
                          build + '\n/* End PBXBuildFile section */')

# 3. Add to Test group children
children_map = {
    'applejpeg_krw.h': ids['krw_h'],
    'applejpeg_krw.m': ids['krw_m'],
    'collector.h': ids['coll_h'],
    'collector.m': ids['coll_m'],
}
for fname, fid in children_map.items():
    ref = f'\t\t\t\t{fid} /* {fname} */,\n'
    if ref not in content:
        # Find the 'Test' group children array and add our files
        content = content.replace(
            '/* Test */ = {\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n',
            f'/* Test */ = {{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = (\n{ref}')

# 4. Add to Sources build phase
for fid in [ids['krw_build'], ids['coll_build']]:
    ref = f'\t\t\t\t{fid} /* applejpeg_krw.m in Sources */,\n' if 'krw' in fid else f'\t\t\t\t{fid} /* collector.m in Sources */,\n'
    if ref not in content:
        content = content.replace(
            'files = (\n',
            f'files = (\n{ref}')

with open(PROJECT, 'w') as f:
    f.write(content)

print(f"Patched {PROJECT}")
for k, v in ids.items():
    print(f"  {k}: {v}")
