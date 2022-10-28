{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    ghidra
    binutils
    file
    binwalk
    steam-run
    python39Packages.pip
    python39Packages.angr
    python39Packages.pwntools
    pwntools
  ];
}
