"""Controls for localized accepted-WOTS sampling and actual caller budgets.

Contract twins check exact theorem sensitivity, not tightness or probability
lower bounds. The cache twin executes the actual memo procedure on a cached
accepted input. Mutated definitions typecheck separately; an equivalent update
must still pass. Timeouts and import/type failures receive no rejection credit.
"""
from addressed_node_controls import imports, lemma_block
from c10_wrapper_security_controls import only_definitions, replace_once
from cert_cone import _decl_span


CONTRACTS = [
    ('conditional-cardinality', 'WotsAcceptedDistribution', 'accepted_word_mass_exact',
     '/22169393903687611906220091621190388%r', '/22169393903687611906220091621190389%r',
     'accepted_word_mass_exact'),
    ('selected-event', 'WotsEncodingCharge', 'selected_collision_is_accepted',
     'selected_accepted_collision h => accepted_wots_encoding_collision h',
     'accepted_wots_encoding_collision h => selected_accepted_collision h',
     '(selected_collision_is_accepted h)'),
    ('seed-width', 'SelectedActualWotsCut', 'selected_actual_partition_cut_cases',
     'size seed=32 => ', '', '(selected_actual_partition_cut_cases h s seed root entries output)'),
    ('adaptive-budget', 'WotsConditionalCollision', 'wots_game_conditional_collision_bound',
     r'WotsMemo.accepted_calls<=n /\ selected_accepted_collision WotsMemo.rawhistory',
     'selected_accepted_collision WotsMemo.rawhistory', '(wots_game_conditional_collision_bound C n &m)'),
    ('cached-charge', 'WotsMemoFacts', 'wots_hash_count',
     'c+b2i(marked /\\ count_accepts res)', 'c', '(wots_hash_count c marked)'),
    ('ordinary-reconstruction', 'WotsByteCount', 'wots_census_byte_count',
     '<=qr+4*qs+2]', '<=qr+2*qs+2]', '(wots_census_byte_count A qr qs)'),
    ('wrapper-reconstruction', 'WotsByteCount', 'wots_census_wrapper_byte_count',
     '<=qr+10*qs+2]', '<=qr+6*qs+2]', '(wots_census_wrapper_byte_count A qr qs)'),
    ('wrapper-internal-verifier', 'WrapperWotsCount', 'wots_census_raw_wrapper_count',
     '<=c+10 /\\', '<=c+8 /\\', '(wots_census_raw_wrapper_count c)'),
    ('final-verifier', 'WotsByteCount', 'wots_census_byte_count',
     '<=qr+4*qs+2]', '<=qr+4*qs]', '(wots_census_byte_count A qr qs)'),
    ('configured-cap', 'WotsByteCount', 'wots_census_wrapper_byte_count',
     r'WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs', 'WrapperLimits.sign_cap=qs',
     '(wots_census_wrapper_byte_count A qr qs)'),
    ('ordinary-physical-hop', 'WotsPoolNumericalBound', 'physical_byte_wots_pool_euf_bound',
     '<= wots_pool_physical_euf_charge qr qs.', '<= wots_pool_independent_euf_charge qr qs.',
     '(physical_byte_wots_pool_euf_bound A qr qs &m)'),
    ('wrapper-physical-hop', 'WrapperWotsPoolNumericalBound', 'wrapper_physical_byte_wots_pool_euf_bound',
     '<= wrapper_wots_pool_physical_euf_charge qr qs.', '<= wrapper_wots_pool_independent_euf_charge qr qs.',
     '(wrapper_physical_byte_wots_pool_euf_bound A qr qs &m)'),
]


def cached_source(port):
    source = (port/'cdrafts-split/WotsMemoOracle.ec').read_text()
    module = _decl_span(source, source.index('module WotsMemo '))
    module = module.replace('module WotsMemo ', 'module CachedWotsControl ')
    return imports(source)+'require import WotsMemoOracle.\n'+module+'''

lemma cached_reply_and_charge x0 d0 c :
  hoare[CachedWotsControl(WotsAcceptedSamples).hash :
    x=x0 /\\ CachedWotsControl.rawhistory.[x0]=Some d0 /\\
    CachedWotsControl.accepted_calls=c /\\ wots_count_query x0 /\\ count_accepts d0 ==>
    res=d0 /\\ CachedWotsControl.rawhistory.[x0]=Some d0 /\\ CachedWotsControl.accepted_calls=c+1].
proof.
  proc; sp 1; rcondf 1; first by auto; smt(domE).
  auto=> /> &m hd _ _ _ ha.
  by rewrite hd /= ?ha.
qed.
'''


def wots_pool_outputs(port):
    outputs = {}

    def save(name, text):
        outputs[port/'scratch'/('wots_pool_'+name.replace('-', '_')+'.ec')] = text.rstrip()+'\n'

    for name, file, theorem, before, after, application in CONTRACTS:
        source = (port/'cdrafts-split'/(file+'.ec')).read_text()
        claim = lemma_block(source, theorem).split('proof.')[0]
        claim = replace_once(claim, 'lemma '+theorem, 'lemma checked')
        changed = replace_once(claim, before, after)
        for mode, statement in [('positive', claim), ('reject', changed)]:
            save(name+'_'+mode, imports(source)+'require import '+file+'.\n'+statement+
                 'proof. exact '+application+'. qed.\n')

    cache = cached_source(port)
    changed = replace_once(cache, 'accepted_calls <- accepted_calls+1;', 'accepted_calls <- accepted_calls+0;')
    equivalent = replace_once(cache, 'accepted_calls <- accepted_calls+1;', 'accepted_calls <- accepted_calls+1+0;')
    save('cache-program-positive', cache)
    save('cache-program-typed', only_definitions(changed))
    save('cache-program-reject', changed)
    save('cache-program-equivalent', equivalent)

    # Keep every other term and alter only the new encoding contribution.
    for file, theorem, charge in [
        ('WotsPoolNumericalBound', 'original_byte_wots_pool_euf_bound',
         'best_wots_encoding_charge (full_public_budget qr qs) (qr+4*qs+2) +'),
        ('WrapperWotsPoolNumericalBound', 'wrapper_query_byte_wots_pool_euf_bound',
         'best_wots_encoding_charge (wrapper_total_public_budget qr qs) (qr+10*qs+2) +')]:
        source = (port/'cdrafts-split'/(file+'.ec')).read_text()
        statement = lemma_block(source, theorem).split('proof.')[0]
        positive = ('require import '+file+'.\n'+only_definitions(source)+statement+
                    'proof. move=> ha hr hs hqr hqs; exact ('+file+'.'+theorem+
                    ' A qr qs &m ha hr hs hqr hqs). qed.\n')
        changed = replace_once(positive, charge, '0%r +')
        prefix = 'ordinary' if file == 'WotsPoolNumericalBound' else 'wrapper'
        save(prefix+'-encoding-positive', positive)
        save(prefix+'-encoding-typed', only_definitions(changed))
        save(prefix+'-encoding-reject', changed)

    header = ('require import AllCore StdOrder.\nrequire import WotsEncodingCharge '
              'AcceptedEncodingPool WotsAcceptedPool WotsAcceptedDistribution.\nimport RealOrder.\n')
    save('minimum-positive', header+'''
lemma witness q n : best_wots_encoding_charge q n<=accepted_encoding_charge q.
proof. exact (best_wots_encoding_charge_retains q n). qed.
''')
    save('minimum-reject', header+'''
lemma checked q n : accepted_encoding_charge q<=best_wots_encoding_charge q n.
proof. exact (best_wots_encoding_charge_retains q n). qed.
''')
    save('budget-equivalent', header+'''
lemma ordinary_regrouped qr qs : qr+2*(1+2*qs)=qr+4*qs+2.
proof. smt(). qed.
lemma wrapper_regrouped qr qs : qr+(4+4+2)*qs+2=qr+10*qs+2.
proof. smt(). qed.
''')
    return outputs


def wots_pool_rows():
    from pathlib import Path
    port = Path(__file__).resolve().parents[1]
    rows = []
    for path in sorted(wots_pool_outputs(port)):
        if path.stem in ('wots_pool_cache_program_reject', 'wots_pool_seed_width_reject'):
            expected, reason = 'MUST-FAIL', '[by]: cannot close goals'
        elif path.stem.endswith('_reject'):
            expected, reason = 'MUST-FAIL', 'the given proof-term proves:'
        else:
            expected, reason = 'MUST-PASS', '-'
        rows.append(str(path.relative_to(port))+'\t'+expected+'\t'+reason)
    return rows
