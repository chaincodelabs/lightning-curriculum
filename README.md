# Lightning Curriculum

| Subjects                        | Topics  | Sub-topics    | Sources |
|---------------------------------|---------|---------------|---------|
What is Lightning?|Introduction||http://lightning.network/lightning-network-paper.pdf, https://coincenter.org/entry/what-is-the-lightning-network, https://medium.com/scalar-capital/the-lightning-network-cf836329626b https://bitcoinmagazine.com/articles/understanding-the-lightning-network-part-building-a-bidirectional-payment-channel-1464710791/ https://bitcoinmagazine.com/articles/understanding-the-lightning-network-part-creating-the-network-1465326903/ https://bitcoinmagazine.com/articles/understanding-the-lightning-network-part-completing-the-puzzle-and-closing-the-channel-1466178980/ https://github.com/ElementsProject/lightning/blob/master/doc/deployable-lightning.pdf https://www.youtube.com/watch?v=8zVzw912wPo https://www.youtube.com/watch?v=b_szGaaPPFk RFC comments: https://medium.com/@rusty_lightning/the-bitcoin-lightning-spec-part-1-8-a7720fb1b4da Glossary: https://en.bitcoin.it/wiki/Lightning_Network|
| |Lightning Layers - an overview||https://www.youtube.com/watch?v=1R5DNUcCYRg |
| |History of LN|| https://www.youtube.com/watch?v=HauP9F16mUM https://bitcoinmagazine.com/articles/future-bitcoin-what-lightning-could-look/ https://bitcoinmagazine.com/articles/history-lightning-brainstorm-beta/ |
Lightning ≈ Bitcoin|||https://www.youtube.com/watch?v=8lMLo-7yF5k |
||Revisting tx malleability||https://www.youtube.com/watch?v=jyDE-aFqJTs |
|Transfer|Payment channel (general concept)||https://wiki.ion.radar.tech/lightning-technology/lightning/payment-channel |
|||Public channel| https://bitcoin.stackexchange.com/questions/80130/in-lightning-network-is-the-balance-publicly-anounced-in-realtime https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-open_channel-message|
|||Private channel|https://blog.lightning.engineering/posts/2018/05/30/routing.html |
|||Channel balance (local/remote)|||
|||Exhausted channels||
|||Channel reserve|https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale |
||Transactions||https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md |
|||Funding Transaction| https://zmnscpxj.github.io/offchain/generalized.html https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#funding-transaction-output https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-funding_created-message|
|||Commitment Transaction| https://en.wikipedia.org/wiki/Lightning_Network#Commitment_transactions https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#commitment-transaction  |
|||Closing Transaction| https://bitcoin.stackexchange.com/questions/80394/closing-a-channel-in-lightning-network https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#closing-transaction |
|||Penalty Transaction| https://bitsonline.com/lightning-network-hackers-busted/ https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#revoked-transaction-close-handling  |
|||Mutual Close| https://medium.com/coinmonks/distinguishing-mutual-and-unilateral-channel-closing-in-the-bitcoin-blockchain-ec2e0e7d71f4 https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#mutual-close-handling  |
|||Unilateral Close|https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#unilateral-close-handling-local-|||commitment-transaction |
|||Fee negotiation|https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#closing-negotiation-||closing_signed |
||HTLC|| https://hackernoon.com/what-are-hashed-timelock-contracts-htlcs-application-in-lightning-network-payment-channels-14437eeb9345 https://rusty.ozlabs.org/?p=462 |
|||Hashlock|https://github.com/bitcoin/bitcoin/pull/7601 |
|||Timelocks| https://medium.com/summa-technology/bitcoins-time-locks-27e0c362d7a1 https://en.bitcoin.it/wiki/Timelock https://medium.com/@RobinHung/bitcoin-timelocks-in-a-nutshell-4c95aafc7a59  |
|||Revocation Key|https://rusty.ozlabs.org/?p=450 |
|||Relative Locktime/CLTV|https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki |
|||Hash Pre-image| https://bitcoin.stackexchange.com/questions/48053/what-is-a-hash-pre-image-as-it-is-used-for-the-breach-remedy https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#offered-htlc-outputs  |
|||payment basepoint/revocation basepoint|https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation |
|||Per-commit secret/Commitment number|https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation |
|||HTLC fulfillment/failure|https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#removing-an-htlc-update_fulfill_htlc-update_fail_htlc-and-update_fail_malformed_htlc |
||Payment|| |
|||Invoice| |
|||Payment Request| |
|Update||Bolt11 encoding|https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md |
|||Gossip Protocol||https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md |
|||LN-Penalty|| |
|||Eltoo payment channels||https://blockstream.com/eltoo.pdf |
|||querying for information| |
|Multihop||| |
Sphinx||| https://wiki.ion.radar.tech/lightning-technology/lightning/sphinx-packet https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf http://diyhpl.us/~bryan/papers2/bitcoin/Sphinx:%20A%20compact%20and%20provably%20secure%20mix%20format.pdf https://cyber.stanford.edu/sites/g/files/sbiybj9936/f/olaoluwaosuntokun.pdf  |
|Onion Routing|||https://www.youtube.com/watch?v=toarjBSPFqI |
||Public vs. Private channel|| https://bitcoin.stackexchange.com/questions/80130/in-lightning-network-is-the-balance-publicly-anounced-in-realtime https://blog.lightning.engineering/posts/2018/05/30/routing.html  |
||Channel announcements||https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-open_channel_message |
||Routing fees||https://blog.bitmex.com/the-lightning-network-part-2-routing-fee-economics/ |
|||Expiry delta||https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#cltv_expiry_delta-selection
||Route hints||https://blog.lightning.engineering/posts/2018/05/30/routing.html |
|Base|Framing and feature negotiation|| |
|Transport ||| |
||Noise Protocol Framework|| http://www.noiseprotocol.org/noise.html#introduction https://www.youtube.com/watch?v=ceGTgqypwnQ  |
||Noise XK|| http://noiseprotocol.org/noise.html#handshake-patterns https://noiseexplorer.com/patterns/XK/  |
Atomic Swaps||| https://coincentral.com/what-are-atomic-swaps-a-beginners-guide/ https://bitcoinmagazine.com/articles/atomic-swaps-how-the-lightning-network-extends-to-altcoins-1484157052/ https://bitcointechtalk.com/atomic-swaps-d6ca26b680fe https://www.youtube.com/watch?v=iuNopQm1Adk |
||Submarine swaps vs. reverse swaps|| https://medium.com/chainrift-research/onboarding-the-masses-submarine-swaps-b615b6d80093 https://www.youtube.com/watch?time_continue=1&v=ASkyu0w_8Q8  |
||Loops|| https://blog.lightning.engineering/posts/2019/03/20/loop.html https://blog.lightning.engineering/technical/posts/2019/||04/15/loop-out-in-depth.html |
Current Limitations||| https://blog.theabacus.io/lightning-network-2-0-b878b9bb356e http://diyhpl.us/wiki/transcripts/boltathon/2019-04-06-alex-bosworth-major-limitations/  |
BOLTs 1.1 and the future||| https://github.com/lightningnetwork/lightning-rfc/wiki/Lightning-Specification-1.1-Proposal-States ||https://blog.lightning.engineering/posts/2018/05/02/lightning-ux.html  |
||Splicing|| https://lists.linuxfoundation.org/pipermail/lightning-dev/2017-May/000692.html https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-October/001434.html  |
||Dual Funded channels||https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-November/001532.html |
||AMP|| https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-February/000993.html https://lists.linuxfoundation.org/||pipermail/lightning-dev/2018-November/001577.html  |
||Rendezvous routing||https://github.com/lightningnetwork/lightning-rfc/wiki/Rendez-vous-mechanism-on-top-of-Sphinx |
|The Future||| |
||Multiparty channels / channel factories|| https://bitcoin.stackexchange.com/questions/67158/what-are-channel-factories-and-how-do-they-work https://www.tik.ee.ethz.ch/file/a20a865ce40d40c8f942cf206a7cba96/Scalable_Funding_Of_Blockchain_Micropayment_Networks%20(1).pdf https://medium.com/chainrift-research/onboarding-the-masses-||channel-factories-6e5c26b07cf1  |
||Decorelation||https://github.com/lightningnetwork/lightning-rfc/wiki/Brainstorming#payment-decorrelation |
||Streaming Payments||https://lists.linuxfoundation.org/pipermail/lightning-dev/2017-September/000757.html |
||Refunds|| |
||Fast Failure|| |
||Scriptless Scripts with ECDSA||https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-May/001244.html |
||Just in time routing||https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-March/001891.html |
| Privacy considerations|||https://bitcoinmagazine.com/articles/how-the-lightning-network-layers-privacy-on-top-of-bitcoin-1482183775/ |
||Gossip protocol and privacy|| |
||watchtowers|| https://diyhpl.us/wiki/transcripts/scalingbitcoin/tokyo-2018/incentivizing-payment-channel-watchtowers/ https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-November/001562.html http://diyhpl.us/wiki/transcripts/boltathon/2019-04-06-conner-fromknecht-watchtowers/ https://www.youtube.com/watch?time_continue=3880&v=nwSuctrzV7Y  |
||Channel probing attack for channel balance|| |
||decorrelation of lightning payments||https://medium.com/@rusty_lightning/decorrelation-of-lightning-payments-7b6579db96b0 |
||SNARKs||https://lists.linuxfoundation.org/pipermail/lightning-dev/2015-November/000309.html |
||Security/Attack Vectors||| |
||Denial of Service attacks|| https://bitsonline.com/state-of-crypto/ https://github.com/lightningnetwork/lightning-rfc/issues/182  |
||Desired topology of a high functional network ||| |
|||Autopilot|| https://www.rene-pickhardt.de/index.html%3Fp=2085.html https://github.com/ElementsProject/lightning/pull/1888  |
|||Channel management||https://diyhpl.us/wiki/transcripts/scalingbitcoin/tokyo-2018/rebalancing-lightning/ |
|||Cyclic Superhubs||https://zmnscpxj.github.io/offchain/cyclicsuperhubs.html |
|Considerations||| |
||Neutrino|| https://vimeo.com/316626387 https://blog.lightning.engineering/posts/2018/10/17/neutrino.html  |
||Pitfalls of concurrent requests|| |
||RGB protocol|| |
||broadcasting channel updates||https://www.reddit.com/r/Bitcoin/comments/714x2k/what_is_the_status_of_the_lightning_network/dn8v3dg/ |
|Implementations||| |
||LND||https://github.com/lightningnetwork/lnd |
||ptarmigan||https://github.com/nayutaco/ptarmigan |
||electrum||https://github.com/spesmilo/electrum/compare/lightning |
||rust||https://github.com/rust-bitcoin/rust-lightning |
||c-lightning||https://github.com/ElementsProject/lightning |
||Eclair||https://github.com/ACINQ/eclair |
Setting up a node||| https://medium.com/andreas-tries-blockchain/bitcoin-lightning-network-1-can-i-compile-and-run-a-node-cd3138c68c15 https://github.com/Stadicus/guides/blob/master/raspibolt/README.md https://medium.com/coinmonks/my-lightning-node-setup-with-c-lightning-45bbb9993c0 https://github.com/rootzoll/raspiblitz |
