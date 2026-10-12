package com.example.klin_kercher.core.url

/**
 * Marca frequentemente imitada em golpes.
 *
 * @param officialDomains domínios da própria empresa. Subdomínios também contam como oficiais.
 * @param keywords termos procurados dentro do endereço (como pedaço de palavra).
 * @param tokens termos curtos, só aceitos como palavra inteira separada por "-" ou "." (ex.: "olx").
 * @param typoTargets nomes comparados por semelhança de escrita (nubnak ≈ nubank).
 * @param excludes palavras legítimas que contêm a marca (amazonas ≠ amazon).
 * @param global marca internacional: aceita o mesmo nome em domínios de países (google.de, amazon.co.uk).
 * @param weak a palavra também é comum no português (ex.: "caixa"); sozinha gera alerta menor.
 */
data class Brand(
    val name: String,
    val officialDomains: List<String>,
    val keywords: List<String> = emptyList(),
    val tokens: List<String> = emptyList(),
    val typoTargets: List<String> = emptyList(),
    val excludes: List<String> = emptyList(),
    val global: Boolean = false,
    val weak: Boolean = false,
) {
    fun isOfficialHost(host: String): Boolean {
        if (officialDomains.any { DomainUtils.isSameOrSubdomain(host, it) }) return true
        if (global) {
            val reg = DomainUtils.registrableDomain(host)
            val label = reg.substringBefore('.')
            val suffix = reg.substringAfter('.', "")
            val officialLabels = officialDomains.map { DomainUtils.mainLabel(it) }.toSet()
            if (label in officialLabels && isCountryOrComSuffix(suffix)) return true
        }
        return false
    }

    private fun isCountryOrComSuffix(suffix: String): Boolean {
        if (suffix == "com") return true
        val parts = suffix.split('.')
        if (parts.size == 1) return parts[0].length == 2
        return parts.size == 2 && parts[1].length == 2 && parts[0] in setOf("com", "co", "org", "net", "ne", "or")
    }
}

/**
 * Cerca de 60 marcas, com foco em bancos, governo e serviços muito usados no Brasil.
 * Para incluir outra marca, basta acrescentar um item nesta lista.
 */
object BrandCatalog {

    val brands: List<Brand> = listOf(
        // ---------- Bancos e pagamentos ----------
        Brand("Nubank", listOf("nubank.com.br", "nu.com.br", "nubank.com", "nu.com.mx", "nu.com.co"),
            keywords = listOf("nubank"), typoTargets = listOf("nubank")),
        Brand("Itaú", listOf("itau.com.br", "itau.com", "itaucard.com.br", "itaupersonnalite.com.br", "itaucultural.org.br",
            "itausa.com.br", "itaubba.com", "itau.cl", "itauunibanco.com.br", "iti.itau"),
            keywords = listOf("itau"), typoTargets = listOf("itaucard", "itauunibanco")),
        Brand("Bradesco", listOf("bradesco.com.br", "bradesco", "bradescocartoes.com.br", "bradescoseguros.com.br", "next.me",
            "bradescard.com.br", "bradescosaude.com.br", "bradescoprevidencia.com.br"),
            keywords = listOf("bradesco", "bradescard"), typoTargets = listOf("bradesco")),
        Brand("Santander", listOf("santander.com.br", "santander.com", "santandernet.com.br", "santanderbrasil.com.br"),
            keywords = listOf("santander"), typoTargets = listOf("santander")),
        Brand("Banco do Brasil", listOf("bb.com.br", "bancodobrasil.com.br"),
            keywords = listOf("bancodobrasil"), tokens = listOf("bb"), typoTargets = listOf("bancodobrasil")),
        Brand("Caixa", listOf("caixa.gov.br", "caixa.com.br"),
            keywords = listOf("caixa", "caixatem", "caixaeconomica", "fgts"), typoTargets = listOf("caixaeconomica"),
            excludes = listOf("caixadesom", "caixapostal", "caixasdesom", "caixadagua", "caixas"), weak = true),
        Brand("Banco Inter", listOf("bancointer.com.br", "inter.co"),
            keywords = listOf("bancointer"), typoTargets = listOf("bancointer")),
        Brand("C6 Bank", listOf("c6bank.com.br", "c6bank.com"), keywords = listOf("c6bank"), typoTargets = listOf("c6bank")),
        Brand("Banco Pan", listOf("bancopan.com.br"), keywords = listOf("bancopan"), typoTargets = listOf("bancopan")),
        Brand("Sicredi", listOf("sicredi.com.br"), keywords = listOf("sicredi"), typoTargets = listOf("sicredi")),
        Brand("Sicoob", listOf("sicoob.com.br"), keywords = listOf("sicoob"), typoTargets = listOf("sicoob")),
        Brand("Banrisul", listOf("banrisul.com.br"), keywords = listOf("banrisul"), typoTargets = listOf("banrisul")),
        Brand("BTG Pactual", listOf("btgpactual.com", "btgpactual.com.br"), keywords = listOf("btgpactual"), typoTargets = listOf("btgpactual")),
        Brand("XP Investimentos", listOf("xpi.com.br", "xpinc.com"), keywords = listOf("xpinvestimentos"), typoTargets = listOf("xpinvestimentos")),
        Brand("Neon", listOf("neon.com.br"), keywords = listOf("banconeon"), typoTargets = listOf("banconeon")),
        Brand("Banco Original", listOf("original.com.br"), keywords = listOf("bancooriginal"), typoTargets = listOf("bancooriginal")),
        Brand("PicPay", listOf("picpay.com", "picpay.com.br"), keywords = listOf("picpay"), typoTargets = listOf("picpay")),
        Brand("Mercado Pago", listOf("mercadopago.com.br", "mercadopago.com"), keywords = listOf("mercadopago"), typoTargets = listOf("mercadopago")),
        Brand("PagBank / PagSeguro", listOf("pagbank.com.br", "pagseguro.com.br", "pagseguro.uol.com.br", "uol.com.br"),
            keywords = listOf("pagseguro", "pagbank"), typoTargets = listOf("pagseguro", "pagbank")),
        Brand("Serasa", listOf("serasa.com.br", "serasaexperian.com.br", "serasaconsumidor.com.br"),
            keywords = listOf("serasa"), typoTargets = listOf("serasa")),

        // ---------- Governo ----------
        Brand("Governo Federal (gov.br)", listOf("gov.br"),
            keywords = listOf("govbr", "receitafederal", "meuinss", "cnhdigital", "cpfregular", "restituicao"),
            tokens = listOf("inss"), typoTargets = listOf("receitafederal")),
        Brand("DETRAN", listOf("gov.br"), keywords = listOf("detran"), weak = true),
        Brand("Correios", listOf("correios.com.br"), keywords = listOf("correios"), typoTargets = listOf("correios")),

        // ---------- Compras ----------
        Brand("Mercado Livre", listOf("mercadolivre.com.br", "mercadolivre.com", "mercadolibre.com", "mlstatic.com"),
            keywords = listOf("mercadolivre", "mercadolibre"), typoTargets = listOf("mercadolivre", "mercadolibre")),
        Brand("Magazine Luiza", listOf("magazineluiza.com.br", "magalu.com", "magalu.com.br"),
            keywords = listOf("magazineluiza", "magalu"), typoTargets = listOf("magazineluiza", "magalu")),
        Brand("Americanas", listOf("americanas.com.br", "americanas.com"), keywords = listOf("americanas"), typoTargets = listOf("americanas")),
        Brand("Casas Bahia", listOf("casasbahia.com.br"), keywords = listOf("casasbahia"), typoTargets = listOf("casasbahia")),
        Brand("Shopee", listOf("shopee.com.br", "shopee.com", "shopee.sg"), keywords = listOf("shopee"), typoTargets = listOf("shopee"), global = true),
        Brand("Amazon", listOf("amazon.com.br", "amazon.com", "amazonaws.com", "amazon.dev", "media-amazon.com", "a2z.com",
            "amazontrust.com", "amazon.jobs", "amazonvideo.com"),
            keywords = listOf("amazon"), typoTargets = listOf("amazon"), excludes = listOf("amazonas", "amazonia"), global = true),
        Brand("AliExpress", listOf("aliexpress.com", "aliexpress.us", "alibaba.com"), keywords = listOf("aliexpress"), typoTargets = listOf("aliexpress"), global = true),
        Brand("Shein", listOf("shein.com", "shein.com.br"), keywords = listOf("shein"), global = true),
        Brand("Temu", listOf("temu.com"), tokens = listOf("temu"), global = true),
        Brand("OLX", listOf("olx.com.br", "olx.com"), tokens = listOf("olx"), global = true),
        Brand("iFood", listOf("ifood.com.br"), keywords = listOf("ifood")),

        // ---------- Serviços e redes sociais ----------
        Brand("Uber", listOf("uber.com"), tokens = listOf("uber"), global = true, weak = true),
        Brand("Netflix", listOf("netflix.com", "nflxext.com", "nflximg.net"), keywords = listOf("netflix"), typoTargets = listOf("netflix"), global = true),
        Brand("Spotify", listOf("spotify.com", "scdn.co", "spotifycdn.com"), keywords = listOf("spotify"), typoTargets = listOf("spotify"), global = true),
        Brand("WhatsApp", listOf("whatsapp.com", "whatsapp.net", "wa.me"), keywords = listOf("whatsapp"), typoTargets = listOf("whatsapp"), global = true),
        Brand("Instagram", listOf("instagram.com", "cdninstagram.com"), keywords = listOf("instagram"), typoTargets = listOf("instagram"), global = true),
        Brand("Facebook / Meta", listOf("facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com", "fbcdn.net", "facebookmail.com"),
            keywords = listOf("facebook"), typoTargets = listOf("facebook"), global = true),
        Brand("Google", listOf("google.com", "google.com.br", "gmail.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "goo.gl", "g.co", "withgoogle.com", "google",
            "googlesyndication.com", "googletagmanager.com", "google-analytics.com", "googlevideo.com",
            "googleadservices.com", "googleblog.com", "googlesource.com", "doubleclick.net"),
            keywords = listOf("google", "gmail"), typoTargets = listOf("google"), global = true),
        Brand("YouTube", listOf("youtube.com", "youtu.be", "ytimg.com"), keywords = listOf("youtube"), typoTargets = listOf("youtube"), global = true),
        Brand("Microsoft", listOf("microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com",
            "sharepoint.com", "onedrive.com", "1drv.ms", "hotmail.com", "windows.com", "azure.com", "msn.com", "bing.com", "xbox.com",
            "microsoftstore.com", "office.net", "skype.com", "windowsupdate.com"),
            keywords = listOf("microsoft", "outlook", "hotmail", "office365", "onedrive", "sharepoint"),
            typoTargets = listOf("microsoft", "outlook", "hotmail"), global = true),
        Brand("Apple", listOf("apple.com", "icloud.com", "apple.news", "mzstatic.com"),
            keywords = listOf("appleid", "icloud", "apple"), typoTargets = listOf("icloud"), excludes = listOf("pineapple", "applebee"), global = true, weak = true),
        Brand("PayPal", listOf("paypal.com", "paypal.me", "paypalobjects.com"), keywords = listOf("paypal"), typoTargets = listOf("paypal"), global = true),
        Brand("Steam", listOf("steampowered.com", "steamcommunity.com", "steamstatic.com", "steamgames.com"),
            keywords = listOf("steampowered", "steamcommunity"), typoTargets = listOf("steampowered", "steamcommunity")),
        Brand("TikTok", listOf("tiktok.com", "tiktokcdn.com", "tiktokv.com"), keywords = listOf("tiktok"), typoTargets = listOf("tiktok"), global = true),
        Brand("LinkedIn", listOf("linkedin.com", "lnkd.in", "licdn.com"), keywords = listOf("linkedin"), typoTargets = listOf("linkedin"), global = true),
        Brand("X / Twitter", listOf("x.com", "twitter.com", "t.co", "twimg.com"), keywords = listOf("twitter"), typoTargets = listOf("twitter"), global = true),
        Brand("Telegram", listOf("telegram.org", "t.me", "telegram.me", "telegra.ph"), keywords = listOf("telegram"), typoTargets = listOf("telegram")),
        Brand("Discord", listOf("discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"),
            keywords = listOf("discord"), typoTargets = listOf("discord")),
        Brand("Dropbox", listOf("dropbox.com", "dropboxusercontent.com", "db.tt"), keywords = listOf("dropbox"), typoTargets = listOf("dropbox")),
        Brand("DocuSign", listOf("docusign.com", "docusign.net"), keywords = listOf("docusign"), typoTargets = listOf("docusign")),

        // ---------- Telefonia ----------
        Brand("Claro", listOf("claro.com.br"), tokens = listOf("claro"), weak = true),
        Brand("Vivo", listOf("vivo.com.br"), tokens = listOf("vivo"), weak = true),
        Brand("TIM", listOf("tim.com.br", "tim.it"), tokens = listOf("tim"), weak = true),

        // ---------- Criptomoedas ----------
        Brand("Binance", listOf("binance.com", "binance.us"), keywords = listOf("binance"), typoTargets = listOf("binance"), global = true),
        Brand("Coinbase", listOf("coinbase.com"), keywords = listOf("coinbase"), typoTargets = listOf("coinbase"), global = true),
        Brand("Mercado Bitcoin", listOf("mercadobitcoin.com.br"), keywords = listOf("mercadobitcoin"), typoTargets = listOf("mercadobitcoin")),
    )

    /** Marca dona do host, se ele for um domínio oficial. */
    fun officialBrandFor(host: String): Brand? = brands.firstOrNull { it.isOfficialHost(host) }

    /** Todos os nomes oficiais (rótulo principal), usados para não confundir uma marca com outra. */
    val allOfficialLabels: Set<String> by lazy {
        brands.flatMap { b -> b.officialDomains.map { DomainUtils.mainLabel(it) } }.toSet()
    }
}
