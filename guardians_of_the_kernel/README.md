# SEKAI CTF 2023 - Guardians of the Kernel

dist: <https://github.com/project-sekai-ctf/sekaictf-2023/tree/main/reverse/guardians-of-the-kernel/dist>

## Writeup

- ioctlのコードが0x7000, 0x7001, 0x7002に分かれてフラグチェックをする
- 各コードにおけるチェックはさほど難しく無いが面倒なのでangrで動くようにしてそれぞれ求める
- 必要だった処置は以下
  - カーネル系のビルトイン関数を差し替え: `printk`と`_copy_from_user`
  - `copy_from_user`の代わりにシンボリックなユーザー空間のバッファを作ってカーネル空間へコピー (`state.memory.store`) する処理を追加
  - `layers`変数 (配列) が非ゼロでないと動かない部分があるので非ゼロにする
  - 各段階で照合が成功したアドレスをIDA等から読み取って`.explore`メソッドの引数に流し込む

ソルバは [solve.py](./solve.py)
