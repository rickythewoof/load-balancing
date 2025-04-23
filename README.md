# Load Balancer
Rete datacenter con diversi servizi e applicatzioni. Ogni servizio (replicato su più macchine fisiche) viene esposto su internet tramite un indirizzo IP. Gli utenti inviano continuamente richieste di servizio, e l'obbiettivo è di **creare un'applicazione SDN per bilanciare il carico di lavoro sui server**.
(praticamente un reverse proxy)
Il carico del server $s_k$ è calcolabile come il rapporto tra
- Domanda
- Disponibilità

$\rho_k(t) = \frac{\sum_in_{i,k}(t)d_i}{b_k}$

L'obbiettivo è di minimizzare il load medio della rete, per ogni istante di tempo, attraverso

$\min_{\forall t}\rho_{max}(t) - \rho_{min}(t)$
1. Client $c_i$ genera una richiesta per il servizio scelto
2. Tramite una `PacketIn` listener la richiesta viene inoltrata all'SDN load balancing
3. Applicazione decide il server a cui assegnare la richiesta
4. Percorso viene configuratol
