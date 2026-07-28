#!/usr/bin/env python3
"""Add exploit source files to an Xcode project's build phase"""
import sys, uuid, re

PROJECT = sys.argv[1] if len(sys.argv) > 1 else 'base/Cyanide.xcodeproj/project.pbxproj'
SOURCES = {
    'Exploit/IOHIDFamilyUAF.m': 'sourcecode.c.objc',
    'Exploit/IOHIDFamilyUAF.h': 'sourcecode.c.h',
    'Payload/collector.m': 'sourcecode.c.objc',
    'Payload/collector.h': 'sourcecode.c.h',
}

with open(PROJECT, 'r') as f:
    content = f.read()

fill_lines = []
build_lines = []
src_lines = []
ids = {}

for name, ftype in SOURCES.items():
    fid = uuid.uuid4().hex[:24].upper()
    bid = uuid.uuid4().hex[:24].upper()
    ids[name] = (fid, bid)
    fill_lines.append(f'\t\t{fid} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = {ftype}; path = {name}; sourceTree = "<group>"; }};')
    if name.endswith('.m'):
        build_lines.append(f'\t\t{bid} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {fid} /* {name} */; }};')
        src_lines.append(f'\t\t\t\t{bid} /* {name} in Sources */,')

content = content.replace(
    '/* End PBXFileReference section */',
    '\n'.join(fill_lines) + '\n/* End PBXFileReference section */')
content = content.replace(
    '/* End PBXBuildFile section */',
    '\n'.join(build_lines) + '\n/* End PBXBuildFile section */')

for name in SOURCES:
    fid = ids[name][0]
    ref = f'\t\t\t\t{fid} /* {name} */,'
    if ref not in content:
        content = content.replace('children = (', f'children = (\n{ref}')

content = content.replace('files = (', 'files = (\n' + '\n'.join(src_lines))

with open(PROJECT, 'w') as f:
    f.write(content)

print(f'Added {len(SOURCES)} files to {PROJECT}')
for name in SOURCES:
    print(f'  {name}')
