"""BLIND / TYPED CALL sub-family — blind-signed calls whose ARGUMENTS the
device can decode and show, one screen per argument.

The device cannot name the function, but it can split the calldata into
its ABI-typed arguments: after the address and the fee screens a flow
here shows ARG 0, ARG 1, … (the ABI's own index, counting from 0), each
argument as the device decodes it — a raw hash read in full, a typed
integer under its type, a boolean, a shortened bytes32, a string, an
array summarised by its count and first item. Identity and endings are
the BLIND family's (flows.blind: the blind mark on the contract-hashed
solid disc, defaults(contract) + ends(subject)); this package only
groups the typed-call flows. Render with
`python -m flows blind/typed_call/<name> --end all` (and --early
--end all for the commit paths)
-> renders/flows/blind/typed_call/<name>/{success,cancel}/<name>_<full|early>_<end>.gif.
"""
