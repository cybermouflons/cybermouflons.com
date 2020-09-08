---
title: '[Facebook CTF 2019] osquery_game'
published: true
tags: [writeup, misc, fbctf19]
author: koks
---

```
We like osquery, emojis, and farm-related video games.

What if we combined them!? Complete all of the quests and win!

ssh osquerygame@challenges.fbctf.com -p2222
password: osquerygame
```

### Solution

```
ssh osquerygame@challenges.fbctf.com -p2222
osquerygame@challenges.fbctf.com's password:
Using a virtual database. Need help, type '.help'
W0604 02:22:52.421134 31921 challenge.cpp:633] Welcome to the osquery farm simulator extension. You have 5 days to make your farm successful.
```

We are connected to an [osquery](https://osquery.io/) shell.

`osquery> .help` displays available commands.  
`osquery> .schema` displays all available tables and their schemata. We notice tables `farm_quests`, `farm_actions`, `farm_emoji` and `farm`.

```
osquery> .all farm_quests
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+
| from       | message                                                                                                                                                                           | done |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+
| Town Mayor | The sheep wants to be next to the pig. Please move him, but be careful, if he sees you he will run away in less than a second, you need to move fast.                             | no   |
| Town Mayor | Please water something that you have planted. You need to pickup a pail first. The sheep was playing with the water pail, if you move him next to his friend he may give it back. | no   |
| Town Mayor | Please pick something that you have grown. Wait a day after planting a seed and watering then pickup your plants.                                                                 | no   |
| Town Mayor | Weeds grow the first day of each season. Be careful, seeds and small plants will be overtaken.                                                                                    | yes  |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+
```

```
osquery> .all farm_actions
+------------------+----------------------------------------------------+
| action           | description                                        |
+------------------+----------------------------------------------------+
| show             | Default action, shows the farm.                    |
| move [src] [dst] | Requests to move animal in SRC field to DST field. |
| pickup [src]     | Pickup item in SRC field.                          |
| water [...dst]   | Water planted herb located at DST.                 |
| plant [...dst]   | Plant a herb in the plowed DST.                    |
+------------------+----------------------------------------------------+
```

```
osquery> .all farm_emoji
+-------+-------------------------------------------------------+
| emoji | meaning                                               |
+-------+-------------------------------------------------------+
| 🌿     | weeds                                                 |
| 🚜     | tractor                                               |
| ⬜     | plowed plot, plant seeds here                         |
| 🐷     | pig                                                   |
| 🚰     | water pail, pick it up, use it to water planted seeds |
| 🐑     | sheep                                                 |
| 🌱     | seedling that needs water                             |
| 🥀     | a dead plant                                          |
| 🍒     | plant                                                 |
| 🌻     | sunflower                                             |
+-------+-------------------------------------------------------+
```

```
osquery> .all farm
W0604 02:23:11.838958 31977 challenge.cpp:512] Good morning! It is day 1/256 🌞
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----+-----+
| farm                                                                                                                                                                                                                                                                                                                                | action | src | dst |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----+-----+
|   0 1 2 3 4 5 6 7 8 9 A B C D E F
0🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🚜🌿🌿🌿🌿
1🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
2🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
3🌿🌿🌿🐑🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
4🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
5🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
6🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
7🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
8🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🐷🌿🌿
9🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
A🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌻🌿🌿
B🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
C🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
D🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
E🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿⬜🌿🌿🌿🌿
F🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
 | show   |     |     |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------+-----+-----+
osquery> E0604 02:23:12.839308 31978 challenge.cpp:457] The sheep was not next to his friend the pig. He saw you and ran away scared.
E0604 02:23:12.839395 31978 challenge.cpp:458] You failed a quest and cannot win the game. Please retry.
```

### Observations

1. As the first quest states, the 🐑 sees us and runs away 😢. We need to be quick. We'll need to automate this with a script.
2. The farm game extension gets triggered every time we query the `farm` table and makes the game progress by 1 day. This is important since we only have 5 days to complete our (4) quests.
3. Since osquery supports `SELECT` statements only, we need to figure out how to issue a game command. `SELECT * FROM farm WHERE action={action_name} AND src={src} AND dst={dst};` does the trick (`src` and `dst` can be in the form of `0xFF`, `0x10` or `255`, `16`)

#### Quest Steps Breakdown

1. Observe farm arrangement (randomly arranged on each session): `.all farm` or `SELECT * FROM farm;`
2. Move the sheep next to pig: `SELECT * FROM farm WHERE action='move' src=0x33 AND dst=0x8D;`
3. Pick up the water plail that the sheep was sitting on: `SELECT * FROM farm WHERE action='pickup' AND src=0x33;`
4. Plant the seeds at one of the plowed plots: `SELECT * FROM farm WHERE action='plant' AND dst=0x1B;`
5. Water the seeds we've planted: `SELECT * FROM farm WHERE action='water' AND dst=0x1B;`
6. Pick up our grown plants: `SELECT * FROM farm WHERE action='pickup' AND src=0x1B;`

We are only 6 steps away from the flag! But wait... That translates to 6 days in the game, we are only allowed 5!

We try this anyway and we get the bad news on day 6:

> E0604 02:55:41.121774 2939 challenge.cpp:506] The farming season is over.

We failed.

Is it possible to combine 2 steps in one query and save a day?  
Nope. Trying to nest more than one `SELECT` statements in a single query:

> E0604 03:02:22.856065 3858 challenge.cpp:516] You can only perform 1 action a day.

Is it possible to move the 🐑 next to the 🐷 without taking a peek at the farm first?  
Nope. This took some time to put together, so it deserves a mention:

```
SELECT farm, action, src, dst, fmt FROM
(SELECT farm, action, src, dst, REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(SUBSTR(farm, 37, 500), 'F', ''), 'E', ''), 'D', ''), 'C', ''), 'B', ''), 'A', ''), '9', ''), '8', ''), '7', ''), '6', ''), '5', ''), '4', ''), '3', ''), '2', ''), '1', ''), '0', ''), CHAR(10), '') as fmt FROM farm LIMIT 1)
WHERE action='move' and src=INSTR(fmt, '🐑') and dst=(INSTR(fmt, '🐷')-1);
```

Glorious. Still a big fat **nope** though. `src` and `dst` need actual numbers there.

### Key Insight

Remember when I said each query on the farm table makes the game progress by 1 day?

> W0604 03:00:35.531996 3600 challenge.cpp:512] Good morning! It is day 4/256 🌞

Well, an accidental infinite loop in our script revealed that if we issue more than 256 queries on the farm table, the season starts over from day 1 again!

That's infinite extra days for us to perform our last action to pickup our 🍒 and complete the game!

One last thing we need to be aware of though, as the 4th quest states:

> Weeds grow the first day of each season. Be careful, seeds and small plants will be overtaken.

So we'll have to plant our seeds in the next season to avoid the following dreaded message:

> W0604 03:46:06.483491 10980 challenge.cpp:501] Some plants or seedlings were overtaken by weeds.

### Solution Script

```python
from pwn import *

def move(src, dst):
    return "SELECT * FROM farm WHERE action='move' and src=%d and dst=%d;" % (src, dst)

def pickup(src):
    return "SELECT * FROM farm WHERE action='pickup' and src=%d;" % (src)

def plant(dst):
    return "SELECT * FROM farm WHERE action='plant' and dst=%d;" % (dst)

def water(dst):
    return "SELECT * FROM farm WHERE action='water' and dst=%d;" % (dst)

def find_positions(farm):
    sheep, pig, plowed_plot = -1, -1, -1
    k = 0
    for i in range(len(farm)):
        for j in range(len(farm[i])):
            if farm[i][j] == u"\U0001f411":  # sheep
                sheep = k
            elif farm[i][j] == u"\U0001F437":  # pig
                pig = k
            elif farm[i][j] == u"\U00002B1C":  # plowed plot
                plowed_plot = k
            k += 1
    return (sheep, pig, plowed_plot)

def main():
    r = ssh("osquerygame", "challenges.fbctf.com",
            port=2222, password="osquerygame")
    sh = r.shell()

    sh.recvuntil("osquery> ")

    # Day 1: View farm
    sh.sendline(".all farm")

    # Parse farm
    farm_display = sh.recv()
    farm_lines = farm_display.split("\n")
    farm = []
    for line in farm_lines[4:]:
        farm.append([x for x in unicode(line, "utf-8").strip()[1:]])

    # Find the positions of interest
    sheep, pig, plowed_plot = find_positions(farm)

    # Day 2: Move sheep next to the left of the pig.
    # This might fail if the spot left of the pig is not available. Just run again.
    sh.sendline(move(sheep, pig-1))
    # Day 3: Pickup water plail that was under the sheep
    sh.sendline(pickup(sheep))

    # Overflow the game's day counter to go to next season
    for i in range(255):
        sh.sendline(".all farm")
        print sh.recv()

    # Day 4: Plant seeds
    sh.sendline(plant(plowed_plot))
    # Day 5: Water seeds
    sh.sendline(water(plowed_plot))
    # Day 6: Pickup plant
    sh.sendline(pickup(plowed_plot))

    sh.interactive()

if __name__ == '__main__':
    main()
```

> E0604 03:55:41.073170 14275 challenge.cpp:582] You completed all quests. Congrats! Your prize is fb{you_win_the_game_again_again}
