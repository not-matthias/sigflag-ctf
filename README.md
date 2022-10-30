# sigflag CTF 2022

## Hardware

## Reversing

## PWN

## Crypto

## Web

## Misc

## Stego

### Mysterious Git

get the dates `git log --pretty=format:"%ad" | cat` and use the hours/minutes as coordinates in a 60x60 image:

```js
const input = `Sat Jan 1 02:45:00 2000 +0100
Sat Jan 1 02:41:00 2000 +0100
...
Sat Jan 1 15:01:00 2000 +0100`;

const result = [];
for (let i = 0; i < 60; ++i) {
  result[i] = [...new Array(60)].fill(" ");
}

const times = input
  .replace(/Sat Jan 1 /gi, "")
  .replace(/:00 2000 \+0100/gi, "")
  .split("\n");

for (const time of times) {
  const [hour, minute] = time.split(":").map((t) => +t);
  result[hour][minute] = "■";
}

console.log(
  result
    .reverse()
    .map((a) => a.join(""))
    .join("\n")
);
```

```
 ■■■■  ■■■   ■■■     ■          ■    ■
■       ■   ■   ■   ■    ■■■   ■■    ■         ■■■
 ■■■    ■   ■      ■    ■   ■   ■   ■■■       ■   ■
    ■   ■   ■  ■■   ■   ■   ■   ■    ■   ■■■  ■   ■
    ■   ■   ■   ■   ■    ■■■■   ■    ■         ■■■■
■■■■   ■■■   ■■■■    ■      ■  ■■■   ■■           ■
                         ■■■                   ■■■

                          ■      ■           ■
■  ■      ■       ■■■    ■ ■    ■ ■   ■       ■
■  ■      ■       ■  ■  ■   ■  ■   ■  ■        ■
■  ■   ■■■■  ■■■  ■  ■  ■   ■  ■   ■  ■■■■    ■
■  ■  ■   ■       ■  ■   ■ ■    ■ ■   ■   ■   ■
 ■■■   ■■■■       ■  ■    ■      ■    ■■■■   ■
```

### Pixel Castle

if you assign the dark squares of the poster `1` and the light squares `0`, then this binary message translates to `The challenge is in another castle!`

![](./flyer.png)

## Forensic

## AI
