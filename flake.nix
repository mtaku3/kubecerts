{
  description = "Kubernetes certificate management tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        kubecerts = pkgs.buildGoModule rec {
          pname = "kubecerts";
          version = "0.1.0";

          src = ./.;

          vendorHash = "sha256-ByNzrxroGpvP1R+fAvTqbhI7mcQB/65/5tIdifW9znI=";

          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
          ];

          meta = with pkgs.lib; {
            description = "Kubernetes certificate management tool";
            homepage = "https://github.com/mtaku3/kubecerts";
            license = licenses.mit;
            maintainers = with maintainers; [ ];
            mainProgram = "kubecerts";
          };
        };
      in
      {
        packages = {
          default = kubecerts;
          kubecerts = kubecerts;
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = kubecerts;
          };
          kubecerts = flake-utils.lib.mkApp {
            drv = kubecerts;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
            go-tools
          ];
        };
      });
}
