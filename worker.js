export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === "POST") {
      try {
        let body;
        try {
          body = await request.json();
        } catch (e) {
          return new Response(JSON.stringify({ success: false, error: "JSON non valido nel body" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (body.tipo === "auth") {
          if (body.code && body.code === env.COMPANY_PASSWORD) {
            const sessionToken = btoa(env.GRIST_API_KEY).substring(0, 30);
            return new Response(JSON.stringify({ 
              success: true, 
              token: sessionToken, 
              urls: { 
                dashboard: env.URL_DASHBOARD, 
                impostazioni: env.URL_IMPOSTAZIONI 
              } 
            }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          } else {
            return new Response(JSON.stringify({ success: false, error: "Codice non valido" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
        }

        const expectedToken = btoa(env.GRIST_API_KEY).substring(0, 30);
        if (!body.token || body.token !== expectedToken) {
          return new Response(JSON.stringify({ success: false, error: "Sessione non autorizzata o scaduta" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        const DOC_ID = env.GRIST_DOC_ID;
        const BASE_GRIST = `https://gestionale-lavoro-emanuel-00.getgrist.com/api/docs/${DOC_ID}/tables`;
        const headersGrist = { "Authorization": `Bearer ${env.GRIST_API_KEY}` };

        // ==========================================
        // GESTIONE CONFIGURAZIONI & APP (LETTURA & SCRITTURA)
        // ==========================================

        if (body.tipo === "get_config_app") {
          const res = await fetch(`${BASE_GRIST}/Config_App/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Config_App" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_config_app") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Config_App/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Valore": String(body.valore), "Descrizione": String(body.descrizione) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Config_App" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_parametri_contrattuali") {
          const res = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_contrattuali") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Anno_Inizio_Validita": parseInt(body.anno_inizio), "Ferie_Annuo_Spettante": parseFloat(body.ferie_annuo), "Permessi_Annuo_Spettante": parseFloat(body.permessi_annuo) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_contrattuali") {
          const resAdd = await fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Anno_Inizio_Validita": parseInt(body.anno_inizio), "Ferie_Annuo_Spettante": parseFloat(body.ferie_annuo), "Permessi_Annuo_Spettante": parseFloat(body.permessi_annuo) } }] })
          });
          if (!resAdd.ok) return new Response(JSON.stringify({ success: false, error: "Errore aggiunta Parametri_contrattuali" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_tipi_assenza") {
          const res = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Tipi_Assenza" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_tipo_assenza") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Nome": String(body.nome), "Blocca_Timbrature": Boolean(body.blocca), "Attivo": Boolean(body.attivo) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Tipi_Assenza" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_tipo_assenza") {
          const nome = String(body.nome || "").trim();
          if (!nome) return new Response(JSON.stringify({ success: false, error: "Nome assenza non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const resAdd = await fetch(`${BASE_GRIST}/Tipi_Assenza/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Nome": nome, "Blocca_Timbrature": Boolean(body.blocca), "Attivo": Boolean(body.attivo) } }] })
          });
          if (!resAdd.ok) return new Response(JSON.stringify({ success: false, error: "Errore aggiunta Tipi_Assenza" }), { status: resAdd.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_tipi_timbratura") {
          const res = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Tipi_Timbratura" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_tipo_timbratura") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Nome": String(body.nome), "Unico_Al_Giorno": Boolean(body.unico), "Attivo": Boolean(body.attivo), "Ordine": parseInt(body.ordine) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Tipi_Timbratura" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "aggiungi_tipo_timbratura") {
          const nome = String(body.nome || "").trim();
          const ordine = Number.parseInt(body.ordine, 10);
          if (!nome || !Number.isInteger(ordine)) return new Response(JSON.stringify({ success: false, error: "Nome o ordine timbratura non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const resAdd = await fetch(`${BASE_GRIST}/Tipi_Timbratura/records`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ fields: { "Nome": nome, "Unico_Al_Giorno": Boolean(body.unico), "Attivo": Boolean(body.attivo), "Ordine": ordine } }] })
          });
          if (!resAdd.ok) return new Response(JSON.stringify({ success: false, error: "Errore aggiunta Tipi_Timbratura" }), { status: resAdd.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_avvisi") {
          const res = await fetch(`${BASE_GRIST}/Avvisi/records`, { headers: headersGrist });
          if (!res.ok) return new Response(JSON.stringify({ success: false, error: "Errore recupero Avvisi" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          const data = await res.json();
          return new Response(JSON.stringify({ success: true, records: data.records || [] }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "modifica_avviso") {
          const idRecord = parseInt(body.id_riga, 10);
          const resMod = await fetch(`${BASE_GRIST}/Avvisi/records`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...headersGrist },
            body: JSON.stringify({ records: [{ id: idRecord, fields: { "Titolo": String(body.titolo), "Messaggio": String(body.messaggio), "Tipo": String(body.tipo_avviso), "Data_Scadenza": Number(body.data_scadenza) || null, "Attivo": Boolean(body.attivo) } }] })
          });
          if (!resMod.ok) return new Response(JSON.stringify({ success: false, error: "Errore modifica Avvisi" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // ==========================================
        // ENDPOINT ESISTENTI (INVARIATI)
        // ==========================================

        if (body.tipo === "get_presenze") {
          const [giorno, mese, anno] = body.data.split('/').map(Number);
          const timestampGristEpoch = Math.floor(Date.UTC(anno, mese - 1, giorno, 0, 0, 0) / 1000);
          const filtroGrist = encodeURIComponent(JSON.stringify({ Data: [timestampGristEpoch] }));
          const responseGrist = await fetch(`${BASE_GRIST}/Prova/records?filter=${filtroGrist}`, { headers: headersGrist });
          if (!responseGrist.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore recupero Grist" }), { status: responseGrist.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const datiGrist = await responseGrist.json();
          const records = datiGrist.records || [];
          const eventosRegistrati = records.map(r => r.fields.Evento);
          return new Response(JSON.stringify({ success: true, eventi: eventosRegistrati, records: records }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "check_assenza") {
          const [giorno, mese, anno] = body.data.split('/').map(Number);
          const epochInizio = Math.floor(Date.UTC(anno, mese - 1, giorno, 0, 0, 0) / 1000);
          const epochFine = Math.floor(Date.UTC(anno, mese - 1, giorno, 23, 59, 59) / 1000);
          
          const [resReg, resTipi] = await Promise.all([
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Tipi_Assenza/records`, { headers: headersGrist })
          ]);
          
          if (!resReg.ok || !resTipi.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore verifica assenze su Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          
          const datiReg = await resReg.json();
          const datiTipi = await resTipi.json();
          
          const mappaBlocco = {};
          (datiTipi.records || []).forEach(t => {
            if (t.fields.Nome) {
              mappaBlocco[t.fields.Nome.trim().toLowerCase()] = Boolean(t.fields.Blocca_Timbrature);
            }
          });

          const assenzeDelGiorno = (datiReg.records || []).filter(r => r.fields.Data >= epochInizio && r.fields.Data <= epochFine);
          const esisteAssenza = assenzeDelGiorno.length > 0;
          const bloccaTimbrature = assenzeDelGiorno.some(r => {
            const nomeTipo = String(r.fields.Tipo_Assenza || "").trim().toLowerCase();
            return mappaBlocco[nomeTipo] === true;
          });

          return new Response(JSON.stringify({ success: true, esiste: esisteAssenza, bloccaTimbrature: bloccaTimbrature }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_report_annuale") {
          const isTutti = (body.anno === "TUTTI");
          const anno_rif = isTutti ? null : parseInt(body.anno);
          if (!isTutti && !anno_rif) return new Response(JSON.stringify({ success: false, error: "Anno non specificato" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

          const [resParametri, resContatori, resAssenze] = await Promise.all([
            fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Contatori/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist })
          ]);
          if (!resParametri.ok || !resContatori.ok || !resAssenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare i dati da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const [parametriData, contatoriData, assenzeData] = await Promise.all([resParametri.json(), resContatori.json(), resAssenze.json()]);

          const getDatiContrattoAnno = (targetAnno) => {
            let f_anno = 25.92, p_anno = 40.0, u_valido = 0;
            for (const config of (parametriData.records || [])) {
              const conf_anno = parseInt(config.fields.Anno_Inizio_Validita || 0);
              if (conf_anno <= targetAnno && conf_anno > u_valido) {
                f_anno = parseFloat(config.fields.Ferie_Annuo_Spettante || 25.92);
                p_anno = parseFloat(config.fields.Permessi_Annuo_Spettante || 40.0);
                u_valido = conf_anno;
              }
            }
            for (const c of (contatoriData.records || [])) {
              if (parseInt(c.fields.Anno || 0) === targetAnno) {
                if (c.fields.Ferie_Annuali_Maturate) f_anno = parseFloat(c.fields.Ferie_Annuali_Maturate);
                if (c.fields.Permessi_Annuali_Maturati) p_anno = parseFloat(c.fields.Permessi_Annuali_Maturati);
                break;
              }
            }
            return { f_anno, p_anno };
          };

          if (isTutti) {
            const anniTrovati = new Set();
            (assenzeData.records || []).forEach(r => { if (r.fields.Data) anniTrovati.add(new Date(r.fields.Data * 1000).getUTCFullYear()); });
            (contatoriData.records || []).forEach(c => { if (c.fields.Anno) anniTrovati.add(parseInt(c.fields.Anno)); });
            if (anniTrovati.size === 0) anniTrovati.add(new Date().getFullYear());

            let tot_f_mat = 0, tot_p_mat = 0;
            anniTrovati.forEach(a => { const d = getDatiContrattoAnno(a); tot_f_mat += d.f_anno; tot_p_mat += d.p_anno; });

            let f_god = 0, f_liq = 0, f_ret = 0, p_god = 0, p_liq = 0, p_ret = 0, malattia_tot = 0;
            for (const r of (assenzeData.records || [])) {
              if (!r.fields.Data) continue;
              const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
              const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
              if (tipo.includes("ferie")) {
                if (tipo.includes("liquidat")) f_liq += qta;
                else if (tipo.includes("rettific")) f_ret += qta;
                else f_god += qta;
              } else if (tipo.includes("permess")) {
                if (tipo.includes("liquidat")) p_liq += qta;
                else if (tipo.includes("rettific")) p_ret += qta;
                else p_god += qta;
              } else if (tipo.includes("malattia")) malattia_tot += qta;
            }

            let testoReport = `========================================\n RIEPILOGO STORICO ANNUALE (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})\n========================================\n\n`;
            testoReport += `MOVIMENTI FERIE CUMULATI\n----------------------------------------\n`;
            testoReport += ` [+] Ferie maturate (somma anni) : +${Math.round(tot_f_mat * 100) / 100} giorni\n`;
            testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(f_god * 100) / 100} giorni\n`;
            if (f_liq > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(f_liq * 100) / 100} giorni\n`;
            if (f_ret > 0.01) testoReport += ` [+/-] Rettifiche ferie (storni): +${Math.round(f_ret * 100) / 100} giorni\n\n\n`;
            testoReport += `MOVIMENTI PERMESSI CUMULATI\n----------------------------------------\n`;
            testoReport += ` [+] Permessi maturati (somma anni) : +${Math.round(tot_p_mat * 100) / 100} ore\n`;
            testoReport += ` [-] Permessi fruiti (ore assenza) : -${Math.round(p_god * 100) / 100} ore\n`;
            if (p_liq > 0.01) testoReport += ` [-] Permessi liquidati/pagate  : -${Math.round(p_liq * 100) / 100} ore\n`;
            if (p_ret > 0.01) testoReport += ` [+/-] Rettifiche permessi (storni): +${Math.round(p_ret * 100) / 100} ore\n\n\n`;
            testoReport += `MALATTIE CUMULATE\n----------------------------------------\n * Giorni di malattia totali    : ${Math.round(malattia_tot * 100) / 100} giorni\n========================================`;

            return new Response(JSON.stringify({ success: true, testoReport, anno: "Tutti_gli_Anni" }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          let { f_anno: ferie_contratto_anno, p_anno: permessi_contratto_anno } = getDatiContrattoAnno(anno_rif);
          let partenza_ferie = 0.0, partenza_permessi = 0.0;
          for (const c of (contatoriData.records || [])) {
            if (parseInt(c.fields.Anno || 0) === anno_rif) {
              partenza_ferie = parseFloat(c.fields.Ferie_Anno_Precedente || 0);
              partenza_permessi = parseFloat(c.fields.Permessi_Anno_Precedente || 0);
              break;
            }
          }

          let f_god = 0, f_liq = 0, f_ret = 0, p_god = 0, p_liq = 0, p_ret = 0, malattia_anno = 0;
          for (const r of (assenzeData.records || [])) {
            if (!r.fields.Data) continue;
            if (new Date(r.fields.Data * 1000).getUTCFullYear() === anno_rif) {
              const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
              const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
              if (tipo.includes("ferie")) {
                if (tipo.includes("liquidat")) f_liq += qta;
                else if (tipo.includes("rettific")) f_ret += qta;
                else f_god += qta;
              } else if (tipo.includes("permess")) {
                if (tipo.includes("liquidat")) p_liq += qta;
                else if (tipo.includes("rettific")) p_ret += qta;
                else p_god += qta;
              } else if (tipo.includes("malattia")) malattia_anno += qta;
            }
          }

          const saldo_ferie = Math.round((partenza_ferie + ferie_contratto_anno - f_god - f_liq + f_ret) * 100) / 100;
          const saldo_permessi = Math.round((partenza_permessi + permessi_contratto_anno - p_god - p_liq + p_ret) * 100) / 100;

          let testoReport = `========================================\n RIEPILOGO ANNUALE COMPLESSIVO: ANNO ${anno_rif}\n========================================\n\n`;
          testoReport += `MOVIMENTI FERIE DELL'ANNO\n----------------------------------------\n`;
          testoReport += ` <<< Residuo anno precedente    : ${partenza_ferie} giorni\n`;
          testoReport += ` [+] Ferie maturate nell'anno   : +${ferie_contratto_anno} giorni\n`;
          testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(f_god * 100) / 100} giorni\n`;
          if (f_liq > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(f_liq * 100) / 100} giorni\n`;
          if (f_ret > 0.01) testoReport += ` [+/-] Rettifiche ferie (storni): +${Math.round(f_ret * 100) / 100} giorni\n`;
          testoReport += `\n >>> SALDO FERIE A FINE ANNO    : ${saldo_ferie} giorni\n\n\n`;
          testoReport += `MOVIMENTI PERMESSI DELL'ANNO\n----------------------------------------\n`;
          testoReport += ` <<< Residuo anno precedente    : ${partenza_permessi} ore\n`;
          testoReport += ` [+] Permessi maturati nell'anno: +${permessi_contratto_anno} ore\n`;
          testoReport += ` [-] Permessi fruiti (ore assenza) : -${Math.round(p_god * 100) / 100} ore\n`;
          if (p_liq > 0.01) testoReport += ` [-] Permessi liquidati/pagati  : -${Math.round(p_liq * 100) / 100} ore\n`;
          if (p_ret > 0.01) testoReport += ` [+/-] Rettifiche permessi (storni): +${Math.round(p_ret * 100) / 100} ore\n`;
          testoReport += `\n >>> SALDO PERMESSI A FINE ANNO : ${saldo_permessi} ore\n\n\n`;
          testoReport += `MALATTIE DELL'ANNO\n----------------------------------------\n * Giorni di malattia nell'anno : ${Math.round(malattia_anno * 100) / 100} giorni\n========================================`;

          return new Response(JSON.stringify({ success: true, testoReport, anno: anno_rif }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "genera_report_mensile") {
          const { anno, mese } = body;
          const mesi_mappatura = { "Gennaio": 1, "Febbraio": 2, "Marzo": 3, "Aprile": 4, "Maggio": 5, "Giugno": 6, "Luglio": 7, "Agosto": 8, "Settembre": 9, "Ottobre": 10, "Novembre": 11, "Dicembre": 12 };
          const mese_rif = mesi_mappatura[mese];
          if (!anno || !mese_rif) return new Response(JSON.stringify({ success: false, error: "Anno o Mese non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

          const [resParametri, resContatori, resAssenze] = await Promise.all([
            fetch(`${BASE_GRIST}/Parametri_contrattuali/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Contatori/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist })
          ]);
          if (!resParametri.ok || !resContatori.ok || !resAssenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare i registri da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const [parametriData, contatoriData, assenzeData] = await Promise.all([resParametri.json(), resContatori.json(), resAssenze.json()]);

          const getParametriPerAnno = (targetAnno) => {
            let f_anno = 25.92, p_anno = 40.0, u_valido = 0;
            for (const config of (parametriData.records || [])) {
              const conf_anno = parseInt(config.fields.Anno_Inizio_Validita || 0);
              if (conf_anno <= targetAnno && conf_anno > u_valido) {
                f_anno = parseFloat(config.fields.Ferie_Annuo_Spettante || 25.92);
                p_anno = parseFloat(config.fields.Permessi_Annuo_Spettante || 40.0);
                u_valido = conf_anno;
              }
            }
            return { coeffFerie: Math.round((f_anno / 12) * 100) / 100, coeffPermessi: Math.round((p_anno / 12) * 100) / 100 };
          };

          if (anno === "TUTTI") {
            const anniTrovati = new Set();
            (assenzeData.records || []).forEach(r => { if (r.fields.Data) anniTrovati.add(new Date(r.fields.Data * 1000).getUTCFullYear()); });
            (contatoriData.records || []).forEach(c => { if (c.fields.Anno) anniTrovati.add(parseInt(c.fields.Anno)); });
            if (anniTrovati.size === 0) anniTrovati.add(new Date().getFullYear());

            let tot_mat_ferie = 0, tot_mat_permessi = 0;
            anniTrovati.forEach(a => { const p = getParametriPerAnno(a); tot_mat_ferie += p.coeffFerie; tot_mat_permessi += p.coeffPermessi; });

            let f_god = 0, f_liq = 0, f_ret = 0, p_god = 0, p_liq = 0, p_ret = 0, mal_tot = 0;
            for (const r of (assenzeData.records || [])) {
              if (!r.fields.Data) continue;
              if ((new Date(r.fields.Data * 1000).getUTCMonth() + 1) === mese_rif) {
                const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
                const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
                if (tipo.includes("ferie")) {
                  if (tipo.includes("liquidat")) f_liq += qta;
                  else if (tipo.includes("rettific")) f_ret += qta;
                  else f_god += qta;
                } else if (tipo.includes("permess")) {
                  if (tipo.includes("liquidat")) p_liq += qta;
                  else if (tipo.includes("rettific")) p_ret += qta;
                  else p_god += qta;
                } else if (tipo.includes("malattia")) mal_tot += qta;
              }
            }

            let testoReport = `========================================\n RIEPILOGO STORICO MESE DI ${mese.toUpperCase()} (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})\n========================================\n\n`;
            testoReport += `MOVIMENTI FERIE DI QUESTO MESE\n----------------------------------------\n`;
            testoReport += ` [+] Ferie maturate (somma anni) : +${Math.round(tot_mat_ferie * 100) / 100} giorni\n`;
            testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(f_god * 100) / 100} giorni\n`;
            if (f_liq > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(f_liq * 100) / 100} giorni\n`;
            if (f_ret > 0.01) testoReport += ` [+/-] Rettifiche ferie (storni): +${Math.round(f_ret * 100) / 100} giorni\n\n\n`;
            testoReport += `MOVIMENTI PERMESSI DI QUESTO MESE\n----------------------------------------\n`;
            testoReport += ` [+] Permessi maturati (somma anni) : +${Math.round(tot_mat_permessi * 100) / 100} ore\n`;
            testoReport += ` [-] Permessi fatti (ore assenza) : -${Math.round(p_god * 100) / 100} ore\n`;
            if (p_liq > 0.01) testoReport += ` [-] Permessi liquidati/pagati  : -${Math.round(p_liq * 100) / 100} ore\n`;
            if (p_ret > 0.01) testoReport += ` [+/-] Rettifiche permessi (storni): +${Math.round(p_ret * 100) / 100} ore\n\n\n`;
            testoReport += `MALATTIE DEL MESE\n----------------------------------------\n * Giorni di malattia nel mese  : ${Math.round(mal_tot * 100) / 100} giorni\n========================================`;

            return new Response(JSON.stringify({ success: true, testoReport, mese, anno: "Tutti_gli_Anni" }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const anno_rif = parseInt(anno);
          const { coeffFerie: coeff_ferie_mese, coeffPermessi: coeff_permessi_mese } = getParametriPerAnno(anno_rif);

          let partenza_ferie = 0.0, partenza_permessi = 0.0;
          for (const c of (contatoriData.records || [])) {
            if (parseInt(c.fields.Anno || 0) === anno_rif) {
              partenza_ferie = parseFloat(c.fields.Ferie_Anno_Precedente || 0);
              partenza_permessi = parseFloat(c.fields.Permessi_Anno_Precedente || 0);
              break;
            }
          }

          let ferie_godute_mese = 0, ferie_liquidate_mese = 0, ferie_rettificate_mese = 0;
          let permessi_fatti_mese = 0, permessi_liquidati_mese = 0, permessi_rettificati_mese = 0, malattia_mese = 0;
          let ferie_cumulate_fino_a_mese = 0, permessi_cumulati_fino_a_mese = 0;
          let ferie_cumulate_mese_precedente = 0, permessi_cumulati_mese_precedente = 0;

          for (const r of (assenzeData.records || [])) {
            if (!r.fields.Data) continue;
            const dataRecord = new Date(r.fields.Data * 1000);
            if (dataRecord.getUTCFullYear() === anno_rif) {
              const tipo = String(r.fields.Tipo_Assenza || "").toLowerCase().trim();
              const qta = parseFloat(String(r.fields.Quantita || 0).replace(",", ".").trim()) || 0;
              const meseRecord = dataRecord.getUTCMonth() + 1;

              if (meseRecord <= mese_rif) {
                if (tipo.includes("ferie")) ferie_cumulate_fino_a_mese += tipo.includes("rettific") ? -qta : qta;
                else if (tipo.includes("permess")) permessi_cumulati_fino_a_mese += tipo.includes("rettific") ? -qta : qta;
              }
              if (meseRecord < mese_rif) {
                if (tipo.includes("ferie")) ferie_cumulate_mese_precedente += tipo.includes("rettific") ? -qta : qta;
                else if (tipo.includes("permess")) permessi_cumulati_mese_precedente += tipo.includes("rettific") ? -qta : qta;
              }
              if (meseRecord === mese_rif) {
                if (tipo.includes("ferie")) {
                  if (tipo.includes("liquidat")) ferie_liquidate_mese += qta;
                  else if (tipo.includes("rettific")) ferie_rettificate_mese += qta;
                  else ferie_godute_mese += qta;
                } else if (tipo.includes("permess")) {
                  if (tipo.includes("liquidat")) permessi_liquidati_mese += qta;
                  else if (tipo.includes("rettific")) permessi_rettificati_mese += qta;
                  else permessi_fatti_mese += qta;
                } else if (tipo.includes("malattia")) malattia_mese += qta;
              }
            }
          }

          const mesi_precedenti_contati = mese_rif - 1;
          const saldo_precedente_ferie = Math.round((partenza_ferie + (coeff_ferie_mese * mesi_precedenti_contati) - ferie_cumulate_mese_precedente) * 100) / 100;
          const saldo_precedente_permessi = Math.round((partenza_permessi + (coeff_permessi_mese * mesi_precedenti_contati) - permessi_cumulati_mese_precedente) * 100) / 100;
          const saldo_reale_ferie_mese = Math.round((partenza_ferie + (coeff_ferie_mese * mese_rif) - ferie_cumulate_fino_a_mese) * 100) / 100;
          const saldo_reale_permessi_mese = Math.round((partenza_permessi + (coeff_permessi_mese * mese_rif) - permessi_cumulati_fino_a_mese) * 100) / 100;

          let testoReport = `========================================\n RIEPILOGO MENSILE: ${mese.toUpperCase()} ${anno_rif}\n========================================\n\n`;
          testoReport += `MOVIMENTI FERIE DI QUESTO MESE\n----------------------------------------\n`;
          testoReport += ` <<< SALDO MESE PRECEDENTE      : ${saldo_precedente_ferie} giorni\n`;
          testoReport += ` [+] Ferie maturate nel mese    : +${coeff_ferie_mese} giorni\n`;
          testoReport += ` [-] Ferie godute (vacanze reali) : -${Math.round(ferie_godute_mese * 100) / 100} giorni\n`;
          if (ferie_liquidate_mese > 0.01) testoReport += ` [-] Ferie liquidate/pagate     : -${Math.round(ferie_liquidate_mese * 100) / 100} giorni\n`;
          if (ferie_rettificate_mese > 0.01) testoReport += ` [+/-] Rettifiche ferie del mese: (Stornati ${Math.round(ferie_rettificate_mese * 100) / 100} gg)\n`;
          testoReport += `\n >>> SALDO FERIE A FINE MESE    : ${saldo_reale_ferie_mese} giorni\n\n\n`;
          testoReport += `MOVIMENTI PERMESSI DI QUESTO MESE\n----------------------------------------\n`;
          testoReport += ` <<< SALDO MESE PRECEDENTE      : ${saldo_precedente_permessi} ore\n`;
          testoReport += ` [+] Permessi maturati nel mese : +${coeff_permessi_mese} ore\n`;
          testoReport += ` [-] Permessi fatti (ore assenza) : -${Math.round(permessi_fatti_mese * 100) / 100} ore\n`;
          if (permessi_liquidati_mese > 0.01) testoReport += ` [-] Permessi liquidati/pagati  : -${Math.round(permessi_liquidati_mese * 100) / 100} ore\n`;
          if (permessi_rettificati_mese > 0.01) testoReport += ` [+/-] Rettifiche permessi mese : (Stornate ${Math.round(permessi_rettificati_mese * 100) / 100} ore)\n`;
          testoReport += `\n >>> SALDO PERMESSI A FINE MESE : ${saldo_reale_permessi_mese} ore\n\n\n`;
          testoReport += `MALATTIE DEL MESE\n----------------------------------------\n * Giorni di malattia nel mese  : ${Math.round(malattia_mese * 100) / 100} giorni\n========================================`;

          return new Response(JSON.stringify({ success: true, message: "Report calcolato", testoReport, mese, anno: anno_rif }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "genera_report_timbrature_mensile" || body.tipo === "get_report_timbrature_annuale") {
          const isMensile = (body.tipo === "genera_report_timbrature_mensile");
          const { anno, mese } = body;
          const isTutti = (anno === "TUTTI");
          const anno_rif = isTutti ? null : parseInt(anno);

          const mesi_mappatura = { "Gennaio": 1, "Febbraio": 2, "Marzo": 3, "Aprile": 4, "Maggio": 5, "Giugno": 6, "Luglio": 7, "Agosto": 8, "Settembre": 9, "Ottobre": 10, "Novembre": 11, "Dicembre": 12 };
          const mese_rif = isMensile ? mesi_mappatura[mese] : null;

          if ((!isTutti && !anno_rif) || (isMensile && !mese_rif)) {
            return new Response(JSON.stringify({ success: false, error: "Parametri Anno o Mese non validi" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }

          const resPresenze = await fetch(`${BASE_GRIST}/Prova/records`, { headers: headersGrist });
          if (!resPresenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Impossibile recuperare le timbrature da Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const presenzeData = await resPresenze.json();

          const giorniMap = {};
          const anniTrovati = new Set();

          for (const r of (presenzeData.records || [])) {
            if (!r.fields || !r.fields.Data) continue;
            const d = new Date(r.fields.Data * 1000);
            const y = d.getUTCFullYear();
            const m = d.getUTCMonth() + 1;
            const g = d.getUTCDate();

            if (!isTutti && y !== anno_rif) continue;
            if (isMensile && m !== mese_rif) continue;

            anniTrovati.add(y);
            const key = `${y}-${String(m).padStart(2, '0')}-${String(g).padStart(2, '0')}`;
            if (!giorniMap[key]) giorniMap[key] = {};

            const ora = parseInt(r.fields.Ora || 0);
            const min = parseInt(r.fields.Minuti || 0);
            giorniMap[key][r.fields.Evento] = (ora * 60) + min;
          }

          let giorniLavorati = 0;
          let giorniCantiere = 0;
          let giorniIncompleti = 0;
          let minutiLavoratiTotali = 0;
          let minutiPausaTotali = 0;
          let minutiStraordinarioTotali = 0;

          Object.values(giorniMap).forEach(ev => {
            if (ev["Cantiere"] !== undefined && ev["Ingresso"] === undefined) {
              giorniCantiere++;
              return;
            }
            if (ev["Ingresso"] !== undefined && ev["Uscita"] !== undefined) {
              giorniLavorati++;
              let lordi = ev["Uscita"] - ev["Ingresso"];
              if (lordi < 0) lordi = 0;

              let pausa = 0;
              if (ev["Inizio Pausa"] !== undefined && ev["Fine Pausa"] !== undefined) {
                pausa = Math.max(0, ev["Fine Pausa"] - ev["Inizio Pausa"]);
              } else if (lordi > 360) {
                pausa = 60;
              }

              const netti = Math.max(0, lordi - pausa);
              minutiLavoratiTotali += netti;
              minutiPausaTotali += pausa;
              if (netti > 480) {
                minutiStraordinarioTotali += (netti - 480);
              }
            } else if (ev["Ingresso"] !== undefined || ev["Uscita"] !== undefined) {
              giorniIncompleti++;
            }
          });

          const formatOre = (minutiTot) => {
            const h = Math.floor(minutiTot / 60);
            const m = Math.round(minutiTot % 60);
            return `${h} ore e ${String(m).padStart(2, '0')} min (${(minutiTot / 60).toFixed(2)} h)`;
          };

          const titoloPeriodo = isMensile
            ? (isTutti ? `${mese.toUpperCase()} (TUTTI GLI ANNI: ${Array.from(anniTrovati).sort().join(', ')})` : `${mese.toUpperCase()} ${anno_rif}`)
            : (isTutti ? `TUTTI GLI ANNI (${Array.from(anniTrovati).sort().join(', ')})` : `ANNO ${anno_rif}`);

          let testoReport = `========================================\n RIEPILOGO TIMBRATURE: ${titoloPeriodo}\n========================================\n\n`;
          testoReport += `PRESENZE E GIORNATE\n----------------------------------------\n`;
          testoReport += ` [+] Giorni lavorati completi   : ${giorniLavorati} giorni\n`;
          if (giorniCantiere > 0) testoReport += ` [+] Giornate solo Cantiere     : ${giorniCantiere} giorni\n`;
          if (giorniIncompleti > 0) testoReport += ` [+/-] Giornate incomplete      : ${giorniIncompleti} giorni\n`;
          testoReport += `\n >>> TOTALE GIORNI REGISTRATI   : ${giorniLavorati + giorniCantiere} giorni\n\n\n`;

          testoReport += `CONTEGGIO ORE LAVORATE\n----------------------------------------\n`;
          testoReport += ` [+] Ore nette lavorate totali  : ${formatOre(minutiLavoratiTotali)}\n`;
          testoReport += ` [-] Ore pausa pranzo detratte  : ${formatOre(minutiPausaTotali)}\n`;
          testoReport += ` [+] Ore straordinario (>8h/gg) : ${formatOre(minutiStraordinarioTotali)}\n`;
          testoReport += `\n >>> TOTALE ORE NETTE PERIODO   : ${(minutiLavoratiTotali / 60).toFixed(2)} ore\n========================================`;

          return new Response(JSON.stringify({
            success: true,
            testoReport,
            mese: isMensile ? mese : null,
            anno: isTutti ? "Tutti_gli_Anni" : anno_rif
          }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "get_storico") {
          const annoFiltro = String(body.anno || new Date().getFullYear());
          const [resPresenze, resAssenze] = await Promise.all([
            fetch(`${BASE_GRIST}/Prova/records`, { headers: headersGrist }),
            fetch(`${BASE_GRIST}/Registro_Ferie_Permessi/records`, { headers: headersGrist })
          ]);
          if (!resPresenze.ok || !resAssenze.ok) {
            return new Response(JSON.stringify({ success: false, error: "Errore API Grist" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const [presenzeData, assenzeData] = await Promise.all([resPresenze.json(), resAssenze.json()]);

          const getTimestamp = (val) => {
            if (!val) return 0;
            if (typeof val === 'number') return val * 1000;
            if (typeof val === 'string' && val.includes('/')) {
              const [gg, mm, aa] = val.split('/');
              const d = new Date(`${aa}-${mm.padStart(2, '0')}-${gg.padStart(2, '0')}T00:00:00Z`);
              return isNaN(d.getTime()) ? 0 : d.getTime();
            }
            const d = new Date(val);
            return isNaN(d.getTime()) ? 0 : d.getTime();
          };

          const filtraEOrdina = (records) => (records || [])
            .filter(r => r.fields && r.fields.Data && getTimestamp(r.fields.Data) !== 0 && new Date(getTimestamp(r.fields.Data)).getUTCFullYear().toString() === annoFiltro)
            .sort((a, b) => getTimestamp(b.fields.Data) - getTimestamp(a.fields.Data));

          return new Response(JSON.stringify({
            success: true,
            presenze: filtraEOrdina(presenzeData.records),
            assenze: filtraEOrdina(assenzeData.records)
          }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (body.tipo === "elimina_record") {
          const tabelleEliminabili = {
            presenze: "Prova",
            assenze: "Registro_Ferie_Permessi",
            registro: "Registro_Ferie_Permessi",
            parametri_contrattuali: "Parametri_contrattuali",
            tipi_timbratura: "Tipi_Timbratura",
            tipi_assenza: "Tipi_Assenza"
          };
          const tabellaId = Object.hasOwn(tabelleEliminabili, body.tabella) ? tabelleEliminabili[body.tabella] : null;
          const idRecord = Number(body.id_riga);
          if (!tabellaId || !Number.isSafeInteger(idRecord) || idRecord <= 0) return new Response(JSON.stringify({ success: false, error: "Tabella o ID record non valido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

          const resElimina = await fetch(`${BASE_GRIST}/${tabellaId}/records/delete`, {
            method: "POST", headers: { ...headersGrist, "Content-Type": "application/json" },
            body: JSON.stringify([idRecord])
          });
          if (!resElimina.ok) return new Response(JSON.stringify({ success: false, error: "Errore durante l'eliminazione su Grist" }), { status: resElimina.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          return new Response(JSON.stringify({ success: true }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        let tabellaId = "";
        let fields = {};
        const idRigaModifica = body.id_riga;

        if (body.tipo === "presenze") {
          tabellaId = "Prova";
          fields = {
            "Data": body.data,
            "Evento": body.evento,
            "Ora": String(body.ore || 0).padStart(2, '0'),
            "Minuti": String(body.minuti || 0).padStart(2, '0'),
            "Note": body.note
          };
        } else if (body.tipo === "registro") {
          tabellaId = "Registro_Ferie_Permessi";
          fields = {
            "Data": body.data,
            "Tipo_Assenza": body.tipoAssenza,
            "Quantita": body.quantita,
            "Note": body.note
          };
        } else {
          return new Response(JSON.stringify({ success: false, error: "Tipo richiesta non riconosciuto" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (idRigaModifica) {
          fields["Ultima_Modifica"] = Math.floor(Date.now() / 1000);
          fields["Note_Modifica"] = body.note_modifica || "Modificato da pannello gestionale";
        }

        const metodoHTTP = idRigaModifica ? "PATCH" : "POST";
        const payloadGrist = idRigaModifica
          ? { records: [{ id: parseInt(idRigaModifica), fields }] }
          : { records: [{ fields }] };

        const response = await fetch(`${BASE_GRIST}/${tabellaId}/records`, {
          method: metodoHTTP,
          headers: { "Content-Type": "application/json", ...headersGrist },
          body: JSON.stringify(payloadGrist)
        });

        const result = await response.json();
        return new Response(JSON.stringify({ success: true, data: result }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    return new Response("Metodo non consentito", { status: 405 });
  }
};