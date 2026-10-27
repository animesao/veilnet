#ifndef __VEILNET_H
#define __VEILNET_H

/* Strategy ids: keep in sync with cli/src/strategies.rs and src/rules/mod.rs.
 * 0 is reserved as "no rule / invalid", matching strategy_to_u8() fallback.
 * Userspace maps STRATEGY_IDS[i] -> i + 1. */
#define VEILNET_STRAT_NONE              1
#define VEILNET_STRAT_MULTISPLIT        2
#define VEILNET_STRAT_MULTISPLIT_SEQOVL 3
#define VEILNET_STRAT_FAKE              4
#define VEILNET_STRAT_FAKE_AGGRESSIVE   5
#define VEILNET_STRAT_FAKE_FAKEDSPLIT   6
#define VEILNET_STRAT_FAKE_MULTIDISORDER 7
#define VEILNET_STRAT_MULTIDISORDER     8
#define VEILNET_STRAT_DISORDER          9
#define VEILNET_STRAT_SPLIT2            10

#define VEILNET_MAX_RULES 10240

#endif /* __VEILNET_H */
