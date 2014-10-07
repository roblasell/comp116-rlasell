
README.txt
Robert Lasell
Comp-116 Computer Security, Fall 2014
Assignment 2: Incident Alarm

===============================

To my knowledge, this project has been fully implemented as specified in the assignment.
This project took me around 10 hours to complete, mostly because I had to learn Ruby.

===============================

1. Are the heuristics used in this assignment to determine incidents "even that good"?

If you are trying to detect these specific incidents (XMAS scan, NULL scan, etc), I think that these heuristics are not bad. You are basically detecting the exact flags and things that make up those incidents, so I would imagine that any tool for detecting these incidents would do something similar, albeit maybe more sophisticated.

2. If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?

I could add some more possible incident types to be detected. I might look into making my regular expressions and such more specific and less "hacky" - for example getting them to determine an incident's payload based on content and not on position relative to the other information.