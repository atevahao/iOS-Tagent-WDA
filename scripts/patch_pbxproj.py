#!/usr/bin/env python3
"""Add exploit source files to an Xcode project's build phase"""
import sys, uuid

PROJECT = sys.argv[1]
SOURCES = {
    'Exploit/IOHIDFamilyUAF.m': 'sourcecode.c.objc',
    'Exploit/IOHIDFamilyUAF.h': 'sourcecode.c.h',
    'Payload/collector.m': 'sourcecode.c.objc',
    'Payload/collector.h': 'sourcecode.c.h',
}

with open(PROJECT, 'r') as f:
    content = f.read()

# Generate IDs
ids = {}
for name, ftype in SOURCES.items():
    ids[name] = {
        'file': uuid.uuid4().hex[:24].upper(),
        'build': uuid.uuid4().hex[:24].upper() if name.endswith('.m') else None,
    }

# 1. Add PBXFileReference entries
entry = '\n'
for name, ftype in SOURCES.items():
    fid = ids[name]['file']
    entry += f'\t\t{fid} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = {ftype}; path = {name}; sourceTree = "<group>"; }};\n'
idx = content.find('/* End PBXFileReference section */')
content = content[:idx] + entry + content[idx:]

# 2. Add PBXBuildFile entries
entry = '\n'
for name in SOURCES:
    if name.endswith('.m'):
        fid = ids[name]['file']; bid = ids[name]['build']
        entry += f'\t\t{bid} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {fid} /* {name} */; }};\n'
idx = content.find('/* End PBXBuildFile section */')
content = content[:idx] + entry + content[idx:]

# 3. Add children to the correct PBXGroup (the one with ViewController.m)
# Find the group that contains ViewController.m
vc_match = None
lines = content.split('\n')
for i, line in enumerate(lines):
    if 'ViewController.m */,' in line and 'children = (' in str(lines[i-1:i+1]):
        vc_match = i
        break

if vc_match:
    # Find the children = ( line before this
    for i in range(vc_match, max(0, vc_match-50), -1):
        if 'children = (' in lines[i]:
            for name in SOURCES:
                fid = ids[name]['file']
                ref = f'\t\t\t\t{fid} /* {name} */,'
                if ref not in content:
                    lines[i] = lines[i] + '\n' + ref
            break

# 4. Add to PBXSourcesBuildPhase (only sources phase)
in_sources = False
sources_phase_i = None
for i, line in enumerate(lines):
    if 'PBXSourcesBuildPhase' in line:
        in_sources = True
    elif in_sources and 'files = (' in line:
        sources_phase_i = i
        break
    elif in_sources and line.strip() == ');':
        in_sources = False

if sources_phase_i:
    for name in SOURCES:
        if name.endswith('.m'):
            bid = ids[name]['build']
            ref = f'\t\t\t\t{bid} /* {name} in Sources */,'
            lines[sources_phase_i] = lines[sources_phase_i] + '\n' + ref

final = '\n'.join(lines)
# Fix double blank lines
while '\n\n\n' in final:
    final = final.replace('\n\n\n', '\n\n')

with open(PROJECT, 'w') as f:
    f.write(final)

print(f'Added {len(SOURCES)} files to {PROJECT}')
for name in SOURCES:
    print(f'  {name}')
