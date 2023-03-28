# Nova

Using https://github.com/nalinbhardwaj/Nova-Scotia

## To run

One time:

- Ensure Circom is setup correctly with Pasta curves (see Nova Scotia README)
- Ensure submodules updates
- Run `npm install` from circom folder
- Run `./examples/sha256/circom/compile.sh`

Then:

`cargo run --example sha256_wasm --release <depth>` where depth is number of recursive hashes to do.git