# Mali Memory Reclaimer for Utgard R5P2

This repository is a mirror of Linux kernel branch from
https://review.tizen.org specially dedicated to the functionality for graphical
buffers reclaiming in Mali Utgard GPU kernel driver.

I was one of the first guys on the planet developed a GPU memory swap solution
for mobile devices.

They are: Dmitry Safonov, Krzystof Kozlowski, Alexander Yashchenko. A similar
solution, but for GEM buffers was prototyped by Sejun Kwon, Sang-Hoon Kim,
Jin-soo Kim and Jinkyu Jeong. Now we know, that the solution for swapping of
GEM buffers is unnecessary, because such buffers can be simply discarded and
reallocated/redrawn when it is necessary.

I also know that a different solution based on shmem was developed in
ARM by Mali driver developers. The project started approximately at the same
time with our own! The solutions are totally different by their nature,
as you can see, and the one published here is little bit more universal.

This repository contains an implementation for Utgard R5P2 driver. The solution
was developed mainly by me. Some code was derived from early prototypes made by
Krzystof Kozlowski, this can be seen in a set of preliminary patches.

Unfortunately I don't know current state of this development, the sources
were contributed to https://review.tizen.org when I worked in Samsung R&D
Institute. Soon, I decided to leave the company, so this is all I have in
public access. The repo represents a content of a development (sandbox)
branch AS IS. I hope that the code was slightly refined before the release,
but I have no info about its possible location on Tizen development resources
(if it was really used on production devices).

You can be also interested in a solution for Midgard GPU developed by Dmitry
Safonov and Alexander Yashchenko: https://github.com/alexhoppus/midgard-gmc.
