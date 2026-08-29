{
  description = "Read cookies from browser profiles in Emacs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.emacsPackages.trivialBuild {
            pname = "browser-cookies";
            version = "0.1.0";
            src = self;
          };
        });

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          tests = pkgs.runCommand "browser-cookies-tests" {
            nativeBuildInputs = [ pkgs.emacs ];
          } ''
            cp -R ${self} source
            chmod -R u+w source
            cd source
            emacs --batch -Q -L . -L test \
              -l test/browser-cookies-test.el \
              -f ert-run-tests-batch-and-exit
            emacs --batch -Q -L . \
              --eval '(setq byte-compile-error-on-warn t)' \
              -f batch-byte-compile browser-cookies.el
            touch $out
          '';
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            packages = [ pkgs.emacs pkgs.gnumake ];
          };
        });
    };
}
