# What is this?

While planning the [Chaincode Residency](https://residency.chaincode.com/), we put considerable effort into finding the best resources and creating a curriculum around Lightning protocol development.

Lightning is still a nascent technology, and so we expect maintenance of this document to be an ongoing task. We could use your help. Please **consider opening a pull-request** to keep this document relevant.

There are three portions to this curriculum:

1. [Study Groups](https://github.com/chaincodelabs/study-groups#lightning) designed to provide bite-sized grouped subjects that you can either complete bookclub style or alone.
2. [Seminar Videos](#seminar-videos) recorded during the Summer 2019 Chaincode Residency.
3. [Lightning Syllabus](#lightning-syllabus) a collection of resources grouped by subjects.


# Seminar Videos

| Session                                 | Topic                      | Link |
|-----------------------------------------|----------------------------|------|
| How pieces fit together | Overall picture | https://youtu.be/krux2v0jt4E |
| How pieces fit together | Update | https://youtu.be/SoFlRCNdqDg |
| How pieces fit together | Transfer | https://youtu.be/CGE8I8L7BAc |
| How pieces fit together | Multihop | https://youtu.be/P7I-C0_sijg |
| How pieces fit together | And the others that are worth mentioning but not exploring (base and transport) | https://youtu.be/wyri7cc83kQ |
| Update layer | Trampoline Payments | https://youtu.be/1WmIjHrjFsg |
| Update layer | Eltoo and the Far Future | https://youtu.be/3ZjymCOmn_A |
| Onion Routing | Atomic multi-path payments (AMP) | https://youtu.be/Og4TGERPZMY |
| Onion Routing | Keysend (formally known as spontaneous payments) | https://youtu.be/zaBY9_eEQWE |
| Update layer - limitations | Fee management | https://youtu.be/r8S3iELg9_U |
| Onion Routing | Deep Dive | https://youtu.be/D4kX0gR-H0Y |
| Update layer - limitations | Incentive problems in the network | https://youtu.be/lByQUr7zPr0 |
| Onion Routing- limitations | Routing failures | https://youtu.be/z5vEyvc2vrE |
| Update layer | Gossip Protocol/Path Finding | https://youtu.be/MeEFUaRnMak |
| Limitations | Payment UX | https://youtu.be/rVgAHMgMCzk |
| Limitations | Limitations of lightweight clients | https://youtu.be/ULVItljEiFE |
| Limitations | Running Lightning in Production | https://youtu.be/fhmeNWczeUg |
| Limitations | Failure modes in action | https://github.com/sstone/ln-in-action|
| | Submarine swaps/ Loops | https://youtu.be/qixhNBIHDyE |
| Attack vectors | Attack vector intro | https://youtu.be/R5cSrftd8nc |
Privacy | Gossip protocol and privacy/How much do watchtowers need to know?/ Minimizing what is broadcasted to the base layer |  https://gist.github.com/adamjonas/8da156886ffa414541eaa43c0c5074ca |
| Privacy | Channel probing attack for channel balance | https://youtu.be/A7rp7bLbZoo, https://github.com/wbobeirne/channel-probing-attack|
| 1.1 and the far future | Network Topology creation/maintenance | https://youtu.be/N7rlHCnaBf8 |
| 1.1 and the far future | Splicing | https://youtu.be/ZzSveBMtUGI |
| 1.1 and the far future | Multi-party channels/Channel factories | https://youtu.be/PUDWGH_MvmQ |
| 1.1 and the far future | Rendezvous Routing | https://youtu.be/Ms2WwRzBdkM |
| 1.1 and the far future | Dual funded channels | https://youtu.be/5wQUMtgsnPs |

# Lightning Syllabus

| Subjects                        | Topics  | Sub-topics    | Sources |
|---------------------------------|---------|---------------|---------|
What is Lightning?|||[The Bitcoin Lightning Network: Scalable Off-Chain Instant Payments](http://lightning.network/lightning-network-paper.pdf), [What is the Lightning Network and how can it help Bitcoin scale?](https://coincenter.org/entry/what-is-the-lightning-network), [The Lightning Network Evolving Bitcoin into a layered system](https://medium.com/scalar-capital/the-lightning-network-cf836329626b), [Understanding the Lightning Network, Part 1: Building a Bidirectional Bitcoin Payment Channel](https://bitcoinmagazine.com/articles/understanding-the-lightning-network-part-building-a-bidirectional-payment-channel-1464710791/), [Understanding the Lightning Network, Part 2: Creating the Network](https://bitcoinmagazine.com/articles/understanding-the-lightning-network-part-creating-the-network-1465326903/), [Understanding the Lightning Network, Part 3: Completing the Puzzle and Closing the Channel](https://bitcoinmagazine.com/articles/understanding-the-lightning-network-part-completing-the-puzzle-and-closing-the-channel-1466178980/), [Reaching The Ground With Lightning](https://github.com/ElementsProject/lightning/blob/master/doc/deployable-lightning.pdf), [Scaling Bitcoin to Billions of Transactions Per Day, 2015](https://www.youtube.com/watch?v=8zVzw912wPo), [Lightning Network Deep Dive with Laolu "Roasbeef" Osuntokun](https://www.youtube.com/watch?v=b_szGaaPPFk), [The #Bitcoin #Lightning Spec](https://medium.com/@rusty_lightning/the-bitcoin-lightning-spec-part-1-8-a7720fb1b4da), [Lightning Network Glossary](https://en.bitcoin.it/wiki/Lightning_Network) |
What is Lightning?|Introduction|Lightning Layers|[How the Lightning Layers Fit Together](https://diyhpl.us/wiki/transcripts/scalingbitcoin/tel-aviv-2019/edgedevplusplus/lightning-network-routing/), [A Lightning Application Design Perspective](https://www.youtube.com/watch?v=1R5DNUcCYRg) |
What is Lightning?|Introduction|History of LN| [History of the Lightning Network](https://www.youtube.com/watch?v=HauP9F16mUM), [The Future of Bitcoin: What Lightning Could Look Like](https://bitcoinmagazine.com/articles/future-bitcoin-what-lightning-could-look/), [The History of Lightning: From Brainstorm to Beta](https://bitcoinmagazine.com/articles/history-lightning-brainstorm-beta/) |
What is Lightning?|Lightning ≈ Bitcoin||[Lightning ≈ Bitcoin](https://www.youtube.com/watch?v=8lMLo-7yF5k) |
What is Lightning?|Lightning ≈ Bitcoin|Revisting tx malleability|[SF Bitcoin Devs Seminar: Transaction Malleability: Threats and Solutions](https://www.youtube.com/watch?v=jyDE-aFqJTs) |
|Transfer|Payment channel| General concept|[Payment Channel](https://wiki.ion.radar.tech/tech/lightning/payment-channel) |
|Transfer|Payment channel|Public channel| [Do the channel balances get publicly announced in real-time on Lightning Network?](https://bitcoin.stackexchange.com/questions/80130/in-lightning-network-is-the-balance-publicly-anounced-in-realtime), [The open_channel Message](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-open_channel-message)|
|Transfer|Payment channel|Private channel|[Exploring Lightning Network Routing](https://blog.lightning.engineering/posts/2018/05/30/routing.html) |
|Transfer|Payment channel|Channel balance (local/remote)||
|Transfer|Payment channel|Exhausted channels||
|Transfer|Payment channel|Channel reserve|[Rationale](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale) |
|Transfer|Transactions|BOLT|[BOLT #3: Bitcoin Transaction and Script Formats](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md) |
|Transfer|Transactions|Funding Transaction| [Funding Transactions as a Generalized Design Pattern for Offchain Protocols](https://zmnscpxj.github.io/offchain/generalized.html), [Funding Transaction Output](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#funding-transaction-output), [The funding_created Message](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-funding_created-message)|
|Transfer|Transactions|Commitment Transaction| [Commitment transactions](https://en.wikipedia.org/wiki/Lightning_Network#Commitment_transactions), [Commitment Transaction](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#commitment-transaction)  |
|Transfer|Transactions|Closing Transaction| [Closing a Channel in Lighting Network](https://bitcoin.stackexchange.com/questions/80394/closing-a-channel-in-lightning-network), [Closing Transaction](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#closing-transaction) |
|Transfer|Transactions|Penalty Transaction| [Lightning Network ‘Penalty Scenario’ Works in Old State Channel Incident](https://bitsonline.com/lightning-network-hackers-busted/), [Revoked Transaction Close Handling](https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#revoked-transaction-close-handling)  |
|Transfer|Transactions|Mutual Close| [Distinguishing mutual and unilateral channel closing in the Bitcoin blockchain](https://medium.com/coinmonks/distinguishing-mutual-and-unilateral-channel-closing-in-the-bitcoin-blockchain-ec2e0e7d71f4), [Mutual Close Handling](https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#mutual-close-handling)  |
|Transfer|Transactions|Unilateral Close|[Unilateral Close Handling: Local Commitment Transaction](https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#unilateral-close-handling-local)|||commitment-transaction |
|Transfer|Transactions|Fee negotiation|[BOLT #2: Peer Protocol for Channel Management](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#closing-negotiation)||closing_signed |
|Transfer|HTLC|Overview| [What Are Hashed Timelock Contracts (HTLCs)? Application In Lightning Network & Payment Channels](https://hackernoon.com/what-are-hashed-timelock-contracts-htlcs-application-in-lightning-network-payment-channels-14437eeb9345),[Lightning Networks Part II: Hashed Timelock Contracts (HTLCs)](https://rusty.ozlabs.org/?p=462) |
|Transfer|HTLC|Hashlock|[HTLC implementation Bitcoin Core](https://github.com/bitcoin/bitcoin/pull/7601) |
|Transfer|HTLC|Timelocks| [Bitcoin’s Time Locks](https://medium.com/summa-technology/bitcoins-time-locks-27e0c362d7a1), [Timelock](https://en.bitcoin.it/wiki/Timelock),[Bitcoin Timelocks in a nutshell](https://medium.com/@RobinHung/bitcoin-timelocks-in-a-nutshell-4c95aafc7a59)  |
|Transfer|HTLC|Revocation Key|[Lightning Networks Part I: Revocable Transactions](https://rusty.ozlabs.org/?p=450) |
|Transfer|HTLC|Relative Locktime/CLTV|[BIP 65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki) |
|Transfer|HTLC|Hash Pre-image| [What is a hash pre-image as it is used for the breach remedy?](https://bitcoin.stackexchange.com/questions/48053/what-is-a-hash-pre-image-as-it-is-used-for-the-breach-remedy),[Offered HTLC Outputs](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#offered-htlc-outputs)  |
|Transfer|HTLC|payment basepoint/revocation basepoint|[Key Derivation](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation) |
|Transfer|HTLC|Per-commit secret/Commitment number|[Key Derivation](https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation) |
|Transfer|HTLC|HTLC fulfillment/failure|[Removing an HTLC: update_fulfill_htlc, update_fail_htlc, and update_fail_malformed_htlc](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#removing-an-htlc-update_fulfill_htlc-update_fail_htlc-and-update_fail_malformed_htlc) |
|Transfer|Payment|Invoice| |
|Transfer|Payment|Payment Request| |
|Update|Invoices|Bolt11 encoding|[BOLT #11: Invoice Protocol for Lightning Payments](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md) |
|Update| Gossip | Gossip Protocol|[BOLT #7: P2P Node and Channel Discovery](https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md) |
|Update| Transactions | LN-Penalty||
|Update| Transactions | Eltoo payment channels|[eltoo: A Simple Layer2 Protocol for Bitcoin](https://blockstream.com/eltoo.pdf) |
|Multihop| Sphinx|Overview| [Sphinx Packet](https://wiki.ion.radar.tech/tech/lightning/sphinx-packet), [Using Sphinx to Improve Onion Routing Circuit Construction (short paper)⋆](https://www.cypherpunks.ca/~iang/pubs/SphinxOR.pdf), [Sphinx: A Compact and Provably Secure Mix Format](http://diyhpl.us/~bryan/papers2/bitcoin/Sphinx:%20A%20compact%20and%20provably%20secure%20mix%20format.pdf), [Security Analysis of the Lightning Network](https://cyber.stanford.edu/sites/g/files/sbiybj9936/f/olaoluwaosuntokun.pdf)  |
|Multihop|Onion Routing| Overview |[Sphinx and Onion routing](https://diyhpl.us/wiki/transcripts/scalingbitcoin/tel-aviv-2019/edgedevplusplus/lightning-network-sphinx-and-onion-routing/), [Onion Routing with HTLCs on the Lightning Network explained! - Beginner / Experts](https://www.youtube.com/watch?v=toarjBSPFqI) |
|Multihop|Onion Routing|Public vs. Private channel| [Do the channel balances get publicly announced in real-time on Lightning Network?](https://bitcoin.stackexchange.com/questions/80130/in-lightning-network-is-the-balance-publicly-anounced-in-realtime),[Exploring Lightning Network Routing](https://blog.lightning.engineering/posts/2018/05/30/routing.html) |
|Multihop|Onion Routing|Channel announcements|[BOLT #2: Peer Protocol for Channel Management](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#the-open_channel_message) |
|Multihop|Onion Routing|Routing fees|[The Lightning Network (Part 2) – Routing Fee Economics](https://blog.bitmex.com/the-lightning-network-part-2-routing-fee-economics/) |
|Multihop|Onion Routing|Expiry delta|[cltv_expiry_delta Selection](https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#cltv_expiry_delta-selection) |
|Multihop|Onion Routing|Route hints|[Exploring Lightning Network Routing](https://blog.lightning.engineering/posts/2018/05/30/routing.html) |
|Base|Framing and feature negotiation|||
|Transport|Noise Protocol Framework| Overview | [The Noise Protocol Framework](http://www.noiseprotocol.org/noise.html#introduction), [The Noise Protocol Framework (video)](https://www.youtube.com/watch?v=ceGTgqypwnQ)  |
|Transport|Noise Protocol Framework|Noise XK|[Handshake patterns](http://noiseprotocol.org/noise.html#handshake-patterns), [Noise Explorer](https://noiseexplorer.com/patterns/XK/)  |
|Atomic Swaps|Introduction| Overview| [What are Atomic Swaps? A Beginner’s Guide](https://coincentral.com/what-are-atomic-swaps-a-beginners-guide/),[Atomic Swaps: How the Lightning Network Extends to Altcoins](https://bitcoinmagazine.com/articles/atomic-swaps-how-the-lightning-network-extends-to-altcoins-1484157052/), [Atomic Swaps](https://bitcointechtalk.com/atomic-swaps-d6ca26b680fe), [Atomic Swaps on the Lightning Network](https://www.youtube.com/watch?v=iuNopQm1Adk) |
|Atomic Swaps| Submarine swaps vs. reverse swaps|Overview| [Onboarding the Masses: Submarine Swaps](https://medium.com/chainrift-research/onboarding-the-masses-submarine-swaps-b615b6d80093), [Submarine Swaps on the Lightning Network](https://www.youtube.com/watch?time_continue=1&v=ASkyu0w_8Q8)  |
|Atomic Swaps|Loops|Overview|[Announcing Lightning Loop Alpha: An Easier Way to Receive on Lightning](https://blog.lightning.engineering/posts/2019/03/20/loop.html),[Loop Out In-depth](https://blog.lightning.engineering/technical/posts/2019/04/15/loop-out-in-depth.html) |
|Current Limitations||| [Lightning Network 2.0](https://blog.theabacus.io/lightning-network-2-0-b878b9bb356e), [Major Limitations of the Lightning Network](http://diyhpl.us/wiki/transcripts/boltathon/2019-04-06-alex-bosworth-major-limitations/)  |
|BOLTs 1.1 and the future|Proposal States|| [Lightning Specification 1.1 Proposal States](https://github.com/lightningnetwork/lightning-rfc/wiki/Lightning-Specification-1.1-Proposal-States), [Lightning User Experience: A Day in the Life of Carol](https://blog.lightning.engineering/posts/2018/05/02/lightning-ux.html)  |
|BOLTs 1.1 and the future|Liquidity|Splicing| [Channel top-up](https://lists.linuxfoundation.org/pipermail/lightning-dev/2017-May/000692.html), [Splicing Proposal](https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-October/001434.html)  |
|BOLTs 1.1 and the future|Liquidity|Dual Funded channels| [Proposal for Advertising Channel Liquidity](https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-November/001532.html)|
|BOLTs 1.1 and the future|Payments|AMP| [AMP: Atomic Multi-Path Payments over Lightning](https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-February/000993.html), [Base AMP](https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-November/001577.html)  |
|BOLTs 1.1 and the future|Routing|Rendezvous routing|[Rendez vous mechanism on top of Sphinx](https://github.com/lightningnetwork/lightning-rfc/wiki/Rendez-vous-mechanism-on-top-of-Sphinx) |
|The Far Future|Routing|Just in time routing|[Just in Time Routing (JIT-Routing) and a channel rebalancing heuristic as an add on for improved routing success in BOLT 1.0](https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-March/001891.html) |
|The Far Future|Onboarding|Multiparty channels / channel factories|[What are Channel Factories and how do they work?](https://bitcoin.stackexchange.com/questions/67158/what-are-channel-factories-and-how-do-they-work), [Onboarding the Masses: Channel Factories](https://medium.com/chainrift-research/onboarding-the-masses-channel-factories-6e5c26b07cf1)  |
|The Far Future|Payments|Decorelation|[Payment Decorrelation](https://github.com/lightningnetwork/lightning-rfc/wiki/Brainstorming#payment-decorrelation) |
|The Far Future|Payments|Streaming Payments|[BOLT 11, real time micro payments, and route redundancy](https://lists.linuxfoundation.org/pipermail/lightning-dev/2017-September/000757.html) |
|The Far Future|Payments|Refunds||
|The Far Future|Payments|Fast Failure||
|The Far Future|Scripts|Scriptless Scripts with ECDSA|[Scriptless Scripts with ECDSA](https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-May/001244.html) |
| Privacy considerations|||[How the Lightning Network Layers Privacy on Top of Bitcoin](https://bitcoinmagazine.com/articles/how-the-lightning-network-layers-privacy-on-top-of-bitcoin-1482183775/) |
|Privacy considerations|Watchtowers|| [Incentivizing payment channel watchtower](https://diyhpl.us/wiki/transcripts/scalingbitcoin/tokyo-2018/incentivizing-payment-channel-watchtowers/),[Trustless Watchtowers](https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-November/001562.html), [Architecture of LND Watchtowers](http://diyhpl.us/wiki/transcripts/boltathon/2019-04-06-conner-fromknecht-watchtowers/) [Incentivizing Payment Channel Watchtowers](https://www.youtube.com/watch?time_continue=3880&v=nwSuctrzV7Y)  |
|Privacy considerations|Channel probing attack for channel balance|| [On the Difficulty of Hiding the Balance of Lightning Network Channels](https://eprint.iacr.org/2019/328.pdf)|
|Privacy considerations|Decorrelation of lightning payments||[Decorrelation of Lightning Payments](https://medium.com/@rusty_lightning/decorrelation-of-lightning-payments-7b6579db96b0) |
|Privacy considerations|SNARKs||[Better privacy with SNARKs](https://lists.linuxfoundation.org/pipermail/lightning-dev/2015-November/000309.html) |
|Security/Attack Vectors|Denial of Service attacks|| [State of the Crypto: Lightning Network DDoS’d](https://bitsonline.com/state-of-crypto/), [Payment channel congestion via spam-attack](https://github.com/lightningnetwork/lightning-rfc/issues/182)  |
|Considerations|Desired topology of a high functional network |Autopilot| [Improving the autopilot of bitcoin’s lightning network](https://www.rene-pickhardt.de/index.html%3Fp=2085.html), [Autopilot PR in c-lightning](https://github.com/ElementsProject/lightning/pull/1888)  |
|Considerations|Desired topology of a high functional network |Channel management| [Lightning network topology Considerations](https://diyhpl.us/wiki/transcripts/scalingbitcoin/tel-aviv-2019/edgedevplusplus/lightning-network-topology/), [Rebalancing in the lightning network: Analysis and implications](https://diyhpl.us/wiki/transcripts/scalingbitcoin/tokyo-2018/rebalancing-lightning/) |
|Considerations|Desired topology of a high functional network |Cyclic Superhubs|[Cyclic Superhubs as Solution Towards Reasonable Lightning Network Topology](https://zmnscpxj.github.io/offchain/cyclicsuperhubs.html) |
|Considerations|Neutrino|| [Exploring Neutrino](https://vimeo.com/316626387), [Neutrino: The Lighter Side of Lightning](https://blog.lightning.engineering/posts/2018/10/17/neutrino.html )|
|Considerations|Pitfalls of concurrent requests|| |
|Considerations|Broadcasting channel updates||[What is the status of the Lightning Network?](https://www.reddit.com/r/Bitcoin/comments/714x2k/what_is_the_status_of_the_lightning_network/dn8v3dg/) |
|Implementations|LND||[Lightning Network Daemon](https://github.com/lightningnetwork/lnd) |
|Implementations|ptarmigan||[Ptarmigan](https://github.com/nayutaco/ptarmigan) |
|Implementations|electrum||[Electrum Implementation in Python](https://github.com/spesmilo/electrum), see `electrum/ln*.py` |
|Implementations|rust-lightning|Incomplete implementation|[Rust-Lightning](https://github.com/rust-bitcoin/rust-lightning) |
|Implementations|c-lightning||[c-lightning — a Lightning Network implementation in C](https://github.com/ElementsProject/lightning) |
|Implementations|Eclair||[Eclair - A scala implementation of the Lightning Network](https://github.com/ACINQ/eclair) |
|Implementations|DotNetLightning|Incomplete implementation|[Lightning network daemon with F#](https://github.com/joemphilips/DotNetLightning) |
|Implementations|geelightning|Incomplete implementation|[geelightning](https://gitlab.com/nblockchain/geelightning) in Rust |
|Setting up a node||| [Bitcoin Lightning Network #1: Can I compile and run a node?](https://medium.com/andreas-tries-blockchain/bitcoin-lightning-network-1-can-i-compile-and-run-a-node-cd3138c68c15), [Beginner’s Guide to ️Lightning️ on a Raspberry Pi](https://github.com/Stadicus/guides/blob/master/raspibolt/README.md), [My Lightning Node setup with c-lightning](https://medium.com/coinmonks/my-lightning-node-setup-with-c-lightning-45bbb9993c0), [Fastest and cheapest way to get your own Lightning Node running - on a RaspberryPi with a nice LCD](https://github.com/rootzoll/raspiblitz) |


## Acknowledgements

Special thanks to [Fabian Jahr](https://github.com/fjahr), [Christian Decker](https://github.com/cdecker), [Fabrice Drouin](https://github.com/sstone), [René Pickhardt](https://github.com/renepickhardt), and [Alex Bosworth](https://github.com/alexbosworth) for their help in putting together the above resources.
