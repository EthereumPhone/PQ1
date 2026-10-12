// Independent nonce preimage and bit-window oracle for the unchanged header.
fn header_window(d: &[u8; 32], offset: usize, width: usize) -> u32 {
    (0..width).fold(0, |value, j| {
        let bit = offset + j;
        value | (u32::from((d[31-bit/8] >> (bit%8)) & 1) << j)
    })
}

fn header_trial(sk: &[u8; 32], seed: &[u8; 16], root: &[u8; 16], msg: &[u8; 32],
    opt: Option<&[u8; 16]>, nonce: u32) -> ([u8; 16], [u8; 32]) {
    let mut preimage = sk.to_vec();
    preimage.extend_from_slice(b"R_grind");
    if let Some(rand) = opt { preimage.extend_from_slice(rand); }
    preimage.extend_from_slice(msg);
    preimage.extend_from_slice(&[0; 28]);
    preimage.extend_from_slice(&nonce.to_be_bytes());
    let r: [u8; 16] = Sha256::digest(preimage)[..16].try_into().unwrap();
    let mut preimage = Vec::new();
    for word in [seed, root, &r] {
        preimage.extend_from_slice(word);
        preimage.extend_from_slice(&[0; 16]);
    }
    preimage.extend_from_slice(msg);
    preimage.extend_from_slice(&[255; 32]);
    (r, Sha256::digest(preimage).into())
}

#[test]
fn sign_header_corpus() {
    let mut output = String::from("-- Independent nonce preimage/window oracle, both OptRand modes.\nnamespace SignHeaderDiff\nstructure Vector where\n  sk : Array UInt8\n  seed : Array UInt8\n  root : Array UInt8\n  message : Array UInt8\n  opt : Option (Array UInt8)\n  nonce : Nat\n  digest : Array UInt8\n  signature : String\n  indices : Array Nat\n  ht : Nat\n  deriving Inhabited\ndef vectors : List Vector := [\n");
    for case in 0..2 {
        let sk = std::array::from_fn(|i| serialization_byte(case, 1, i));
        let seed = std::array::from_fn(|i| serialization_byte(case, 2, i));
        let root = std::array::from_fn(|i| serialization_byte(case, 3, i));
        let rand = std::array::from_fn(|i| serialization_byte(case, 4, i));
        let opt = if case == 0 { None } else { Some(&rand) };
        // Only select cheap fixed messages; do not alter the production search.
        let witness = (0..100_000u32).find_map(|salt| {
            let mut msg = std::array::from_fn(|i| serialization_byte(case, 5, i));
            msg[28..].copy_from_slice(&salt.to_be_bytes());
            (0..16u32).find_map(|nonce| {
                let (r,digest) = header_trial(&sk,&seed,&root,&msg,opt,nonce);
                (header_window(&digest,132,11)==0).then_some((msg,nonce,r,digest))
            }).filter(|(_,nonce,_,_)| if case==0 { *nonce==0 } else { *nonce>0 })
        }).expect("cheap header witness absent");
        let (msg,nonce,r,digest) = witness;
        for earlier in 0..nonce {
            assert_ne!(header_window(&header_trial(&sk,&seed,&root,&msg,opt,earlier).1,132,11),0);
        }
        let indices: [u32;13] = std::array::from_fn(|j| header_window(&digest,j*11,11));
        let ht = header_window(&digest,143,18);
        let mut expected = [0u8;4008]; expected[..16].copy_from_slice(&r);
        let mut padded = [0u8;32]; padded[..16].copy_from_slice(&seed);
        let actual = sign_header_fragment(&sk,&seed,&root,&msg,opt,&progress_none());
        assert_eq!(actual,(padded,expected,indices,ht,16,digest),"header case {case}");
        assert_eq!(indices[12],0); assert!(indices.iter().all(|&i| i<2048)); assert!(ht<262144);
        let opt_text = match opt {None=>"none".to_string(),Some(x)=>format!("some ({})",array(x))};
        let ix = format!("#[{}]",indices.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "));
        output.push_str(&format!("{{ sk := {}, seed := {}, root := {}, message := {}, opt := {opt_text}, nonce := {nonce}, digest := {}, signature := \"{}\", indices := {ix}, ht := {ht} }},\n",array(&sk),array(&seed),array(&root),array(&msg),array(&digest),serialization_hex(&expected)));
        println!("header case {case}: nonce {nonce}, ht {ht}, leaves {}/{}",ht%512,(ht/512)%512);
    }
    output.push_str("]\nend SignHeaderDiff\n");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../extracted/Extracted/SignHeaderDiffVectors.lean");
    if std::env::var("PQ_SIGN_HEADER_GENERATE").as_deref()==Ok("1") {std::fs::write(path,output).unwrap();}
    else {assert_eq!(std::fs::read_to_string(path).unwrap(),output,"header corpus drift");}
    println!("OK: both OptRand modes, first nonce zero/nonzero, all header bytes, padding, indices, forced-zero and hypertree index match an independent oracle");
}
