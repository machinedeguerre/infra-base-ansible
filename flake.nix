{
  description = "infra-base-ansible dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Pinned Nebula build (v1.10.3)
        nebula_1_10_3 = pkgs.buildGoModule rec {
          pname = "nebula";
          version = "1.10.3";

          src = pkgs.fetchFromGitHub {
            owner = "slackhq";
            repo = "nebula";
            rev = "v${version}";
            hash = "sha256-sF/NZpBxbJWHTjx6Nuv7WHgUqhYbBq2/g7nB3wxNDHg=";
          };

           # First run: use lib.fakeHash, then replace with the real hash from the error output.
          vendorHash = "sha256-zzYywNbeccW4Ujig20oBUZsJBQFvCIkCNOuBMxGxaqE=";

          # Install both binaries.
          subPackages = [ "." "cmd/nebula-cert" ];

          ldflags = [
            "-s" "-w"
            "-X=main.version=v${version}"
          ];

          meta = with pkgs.lib; {
            description = "Nebula (pinned) - secure overlay networking tool";
            homepage = "https://github.com/slackhq/nebula";
            license = licenses.mit;
          };
        };

      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            ansible
            bind.dnsutils
            certbot
            git
            nebula_1_10_3
            openssl
            python3
            zip
          ];

          shellHook = ''
            export ANSIBLE_FORCE_COLOR=1
            echo "Dev shell ready: $(ansible --version | head -n1)"
            echo "Tools: ansible-galaxy, ansible-playbook"
          '';
        };
      });
}
