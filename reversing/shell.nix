{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    ghidra
    binutils
    file
    binwalk
  ];
}
