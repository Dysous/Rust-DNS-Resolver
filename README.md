[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/mun0VlAh)
Goal: Apply the knowledge you've learned in new ways.

# Project description
This is an open-ended project. Students can extend their BearTV project or do something new from the ground up. Project ideas must be approved by Dr. Freeman.

You must give a **formal presentation** of your project in place of a final exam. Each group will have ~12 minutes to present their work. Each member of the group must speak. You should have slides. Your presentation must include a demo of your project, although it may include a pre-recorded screen capture. In your presentation, you should introduce the problem that you addressed, how you addressed it, technical challenges you faced, what you learned, and next steps (if you were to continue developing it).

You may use AI LLM tools to assist with the development of your project, including code assistant tools like GitHub Copilot. If you do use any AI tools, you must describe your use during your presentation.

Unless you get specific approval otherwise, your project **must** include some component deployed on a cloud hosting service. You can use AWS, GCP, Azure, etc. These services have free tiers, and you might consider looking into tiers specifically for students.

**Graduate students enrolled in CSI-5321:** You have additional requirements. See the bottom of the README.

## Milestones
- You must present your project idea to Dr. Freeman within the first week to get it approved
- You must meet with Dr. Freeman within the first 3 weeks to give a status update and discuss roadblocks
- See the course schedule spreadsheet for specific dates

## Project Ideas
- Simulate UDP packet loss and packet corruption in BearTV in a non-deterministic way (i.e., don't just drop every Nth packet). Then, extend the application protocol to be able to detect and handle this packet loss.
- Extend the BearTV protocol to support streaming images (or video!) alongside the CC data, and visually display them on the client. This should be done in such a way that it is safely deliver*able* over *any* implementation of IPv4. The images don't have to be relevant to the caption data--you can get them randomly on the server from some image source.
- Do something hands-on with a video streaming protocol such as MoQ, DASH, or HLS.
- Implement QUIC
- Develop a new congestion control algorithm and evaluate it compared to existing algorithms in a realistic setting
- Make significant contributions to a relevant open-source repository (e.g., moq-rs)
- Implement a VPN
- Implement a DNS
- Do something with route optimization
- Implement an HTTP protocol and have a simple website demo

→ These are just examples. I hope that you'll come up with a better idea to suit your own interests!

## Libraries

Depending on the project, there may be helpful libraries you find to help you out. However, there may also be libraries that do all the interesting work for you. Depending on the project, you'll need to determine what should be fair game. For example, if your project is to implement HTTP, then you shouldn't leverage an HTTP library that does it for you.

If you're unsure if a library is okay to use, just ask me.

## Languages

The core of your project should, ideally, be written in Rust. Depending on the project idea, however, I'm open to allowing the use of other languages if there's a good reason for it. For me to approve such a request, the use of a different language should enable greater learning opportunities for your group.

# Submission

## Questions
- What is your project?
	- Our project is a DNS resolver written in Rust that supports traditional UDP DNS queries and DoH (DNS over HTTPS). 
Our resolver included a packet parser, caching with TTL expiration, DNSSEC validation/signing, pi-hole domain blocking 
(ad blocker engine), threat detection for suspicious DNS activity and identifying DNS tunneling, and a live statistics 
monitoring dashboard. 

- What novel work did you do?
  - For the statistics and monitoring infrastructure/dashboard, we worked on the internal API 
endpoints, in-memory logging system, live query stream, cache monitoring page, DNSSEC statistics, and threat 
visualization pages. Most of the work for the website required connecting the separate backend systems together 
and integrating them into the resolver pipeline or exposing them to the frontend. We connected the DNS resolver, 
stats engine, and frontend dashboard pages to track and display live info about blocked domains, threat scores, 
cache hits, tunneling alerts, and DNSSEC activity.

- What did you learn?
  - The initial foundation of our project focused on learning about DNS at the packet level, such as DNS headers, 
name compression, caching, response codes, and DNSSEC records. We also further learned about atomics, mutexes, 
Tokio async networking, and thread safe shared states in Rust programming. We learned how to connect our Rust 
backend to a live monitoring dashboard that continuously updated the DNS statistics by using JSON APIs and 
JavaScript fetch requests.

- What was challenging?
  - When compiling the statistics for our website, my biggest challenge was integration/connection because many systems 
worked independently. For example, the logic for some security and threat-detection components existed but were not 
connected to the resolver loop, stats engine, or frontend APIs, so events were not able to appear on the dashboard 
until further connective code was implemented. Likewise, for each use case this often involved having to change 
logic across 2-4 different files to make sure it was still working correctly and was being tracked accurately.
Another challenge was concurrency and synchronization. Because the resolver handled the network traffic asynchronously, 
it was important to pick whether data (logs, cache, statistics) would be recorded as atomics or mutexes to avoid race 
conditions and deadlocks.
- What AI tools did you use, and what did you use them for? What were their benefits and drawbacks?
  - I used Google Gemini AI to ask questions relating to an issue I had when trying to host our website locally on 
port 8080 while also running the resolver with real traffic using Cargo inside the remote Docker development container 
in Rust Rover (in early development I wanted to avoid changing our AWS main website). It helped me try potential 
solutions and conclude that the website was only accessible inside the terminal/container environment and not 
from my local browser, and thus I needed a different method if I wanted to host the website locally. Benefits were 
that it provided a more knowledgeable view of the schematics than I personally had, and it was able to provide me 
with feedback and potential solutions in real time. A drawback was that I had to push it towards that final 
conclusion based on my personal instinct, as initially it was continuously providing solutions that were simply 
not possible, and in the end, I did end up consulting two members for confirmation and not just trusting the AI’s word.
- What would you do differently next time?
  - There was certain logic choices made within our project that sufficed for the scope of our class knowledge and 
project scope, but if we expanded our project, it may introduce slower output, bottlenecks, or high memory usage. 
For example, if introduced over a million queries to our current UDP listener, the current global lock implementation 
would cause a bottleneck, so if we did the project again, we could explore further on how to handle threads for 
large scale productions.
## What to submit
- Push your working code to the main branch of your team's GitHub Repository before the deadline
- Edit the README to answer the above questions
- On Teams, *each* member of the group must individually upload answers to these questions:
	- What did you (as an individual) contribute to this project?
	- What did the other members of your team contribute?
	- Do you have any concerns about your own performance or that of your team members? Any comments will remain confidential, and Dr. Freeman will try to address them in a way that preserves anonymity.
	- What feedback do you have about this course?

## Grading

Grading will be based on...
- The technical merit of the group's project
- The contribution of each individual group member
- Evidence of consistent work, as revealed during milestone meetings
- The quality of the final presentation

# 5321 Extra requirements

(For graduate students enrolled in CSI-5321)

Your project **must** have a research component to it. That is, you must set out to address an open research question using some networking concepts you've learned in this course. Subject to my approval, this project can be an extension of a project you're currently working on with your advisor.

Along with your code repository and presentation, you must submit a 4+ page paper (plus bibliography), in double-column paper using the [ACM LaTeX template](https://www.acm.org/publications/proceedings-template) under the `sigconf` document class. This paper should include a brief introduction, related work, a description of your approach, experimental results, and a conclusion. Your goal should be to have a paper of high enough quality that it can be easily extended for a full submission to a research conference.

All other instructions for the project apply, including the above submission questions.

## 5321 Research ideas

- Investigate the efficacy of congestion control algorithms for QUIC. Design your own improvements for some application, and evaluate it.
- Propose improvements to, or novel applications of, the Media Over QUIC protocol
- Limitations of QUIC IP switching
- Quality adaptation for lossy data streaming of something other than traditional video
- Distributed databases, federation, or blockchain
- Protocol security flaws
- IoT, Wi-Fi 8, or 6G
- CDN performance (e.g., content steering)
- Live video streaming with distributed super-resolution between server/client for higher quality and lower latency
- Mesh networking
- Machine learning for routing protocols

→ These are just examples. I hope that you'll come up with a better idea to suit your own interests!
