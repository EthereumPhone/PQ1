# QuickSwap V2 Router02 remove-liquidity evidence

This offline bundle binds PQ1's constrained ERC-7730 admission of three
all-static, non-permit removal routes on Polygon. The runtime was captured by
EIP-1898 block hash from four independent public RPC fronts. The archived
official QuickSwap source snapshot and build files match the verified flattened
deployment source under the normalization described in `manifest.json`.

The central display decision is deliberately conservative: `liquidity` is the
exact LP-token base-unit quantity transferred to the pair and burned, but the
pair identity and LP-token decimals are derived rather than signed. PQ1
therefore shows all 32 signed bytes as raw hexadecimal. It does not invent a
ticker or decimal scale.

The fee-on-transfer variant has two live-state residuals that the signed
calldata cannot quantify: its token minimum checks gross pair output rather
than the beneficiary's net post-tax receipt, and it transfers the router's
entire token balance (which can include dust) to the signed beneficiary. These
facts do not hide a signed operand, but they remain explicitly recorded rather
than being presented as stronger output guarantees.

Permit-bearing removal routes and every route with a dynamic swap path remain
known calls that hard-refuse clear signing. This bundle grants no authority to
those routes, to other deployments, or to fallback/blind signing.
