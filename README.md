<!--
SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
SPDX-License-Identifier: LGPL-3.0-only
-->

# rz-probana-zz

Implementations of probabilistic binary analysis algorithms by [Zhuo Zhang (张倬)](https://www.cs.purdue.edu/homes/zhan3299/) 

## Intro

**Papers**

- [All (thesis)](https://doi.org/10.25394/PGS.23542014.v1)
- [BDA](https://www.cs.purdue.edu/homes/zhan3299/res/OOPSLA19.pdf)
- [OSPREY](https://www.cs.purdue.edu/homes/zhan3299/res/SP21a.pdf)
- [StochFuzz](https://www.cs.purdue.edu/homes/zhan3299/res/SP21b.pdf)

## Build

```sh
# Get Rizin
git clone https://github.com/rizinorg/rizin
cd rizin
export RZ_REPO_PATH=$(pwd)
meson setup build
meson compile -C build
sudo meson install -C build
cd ..

cargo build
cargo test --lib
```

## Install

```sh
rizin -H | grep RZ_USER_PLUGINS
mkdir -p <RZ_USER_PLUGINS>
ln -s target/debug/libprobana_zz.so <RZ_USER_PLUGINS>/libprobana_zz.so
```

## Dev

```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r py_requirements.txt
```
