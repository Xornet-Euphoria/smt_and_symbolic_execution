# CTF Advent Calendar 2024

## まえがき

この記事は、[CTF Advent Calendar 2024](https://adventar.org/calendars/10469)の22日目の記事です。

前日の記事は、[rand0mさんの"Know you angr"](https://rndt.pages.dev/private/angr-decompiler-G7MaVwdu3JqrQqIuOxWCbQ45vdcWDxv9Z1GNBIX78XOqOyR/) でした。

angrのCFGはデコンパイラに使える他にかなり強力な解析機能があり、深堀りしてみたいです。ちなみに、ちゃんと整理はしていませんが、このリポジトリでも使っている[箇所](./topology/angr_cfg.py)があります。

## これは何？

> angrかTritonの日本語で書かれていない話を書けたら書く

と、1ヶ月前に宣言したものの、モチベーションの低下と振り返ったらここで書こうと思ったことがそこまで高度ではないことから、10月-11月にかけて諸事情でシンボリック実行で遊んでいた際のまとめリポジトリをあげておきます。だいたい次のような構成です。

- [be_angry](./be_angry/): テンプレスクリプト問題で初学者に教える際に使用
- [everything_silver](./everything_silver/): 抽出したシェルコードや実行トレース等、動的解析の痕跡をangrやTritonで再現する
- [topology](./topology/): フック、breakpoint、CFGの利用
- [eldercmp](./eldercmp/): 軽度なバイナリのパッチとangrで解こうと思ったところで (問題ではなく) シンボリック実行自体のやる気が無くなった

全く整理していないまま出すので不適切な表現 (特に下ネタとF word) が気に食わなかったらこっそり教えたりプルリクで晒し上げたりしてください。

## 終わりに

明日もrand0mさんがなにか書いてくれるそうです (todo: 掲載されたらリンクを生やす)。Revの話題が多い方なので楽しみです。
