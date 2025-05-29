{
  description = "SesameOS3 development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        name = "sesameos3-dev-shell";
        buildInputs = with pkgs; [
          python3
          python3Packages.pycryptodome
          python3Packages.bleak
          python3Packages.aioconsole
        ];
      };
    };
}