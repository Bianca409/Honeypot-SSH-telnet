# SSH & Telnet Protocol State Machines

## 1. Telnet State Machine (Port 2323)
1. **TCP Connection / Handshake**: Clientul se conectează prin TCP la portul `2323` (`honeypot_app`)[cite: 1, 3].
2. **Banner Sent**: Serverul trimite un banner realist (ex. Ubuntu 22.04 LTS) și promptul `login:`.
3. **Username Received**: Se citește numele de utilizator introdus și se cere `Password:`.
4. **Password Received & Logging**: Se captează parola și se salvează tentativa prin logger/storage (`auth_attempts`)[cite: 2, 3].
5. **Decision (MVP vs Shell)**:
   - **REJECT (MVP)**: Se trimite `Login incorrect` și se închide sau se reia fluxul de autentificare.
   - **ACCEPT / TRAP (Sprint 2)**: După condițiile configurate (ex. încercări repetate sau user comun), se intră în Fake Shell și se loghează comenzile (`shell_commands`)[cite: 2, 4].

## 2. SSH State Machine (Port 2222)
1. **TCP & SSH Handshake**: Clientul se conectează pe portul `2222` (`asyncssh`), se negociază versiunea și se schimbă cheile (cu chei host generate automat)[cite: 1, 4].
2. **Banner Exchange**: Se expune banner-ul SSH (ex. `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1`)[cite: 4].
3. **Authentication Attempt**: Clientul trimite credențialele (username + password)[cite: 4].
4. **Logging**: Tentativa este trimisă către logger/storage (`auth_attempts`)[cite: 2, 4].
5. **Decision (MVP vs Shell)**:
   - **REJECT (MVP)**: Autentificarea este respinsă conform fluxului MVP[cite: 4].
   - **ACCEPT / TRAP (Sprint 2)**: Redirecționare în Fake Shell și logarea comenzilor (`shell_commands`)[cite: 2, 4].