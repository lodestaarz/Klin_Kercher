package com.example.klin_kercher.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.DrawableRes
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.example.klin_kercher.R
import com.example.klin_kercher.ui.screens.BaseScreen
import com.example.klin_kercher.ui.screens.FilesScreen
import com.example.klin_kercher.ui.screens.LinksScreen

private val Tab.label: String
    get() = when (this) {
        Tab.LINKS -> "Links"
        Tab.FILES -> "Arquivos"
        Tab.BASE -> "Base local"
    }

@get:DrawableRes
private val Tab.icon: Int
    get() = when (this) {
        Tab.LINKS -> R.drawable.ic_link
        Tab.FILES -> R.drawable.ic_file
        Tab.BASE -> R.drawable.ic_database
    }

@Composable
fun KlinKercherApp(vm: MainViewModel) {
    val tab by vm.tab.collectAsState()
    val links by vm.links.collectAsState()
    val files by vm.files.collectAsState()
    val base by vm.base.collectAsState()

    // Seletores de arquivo do sistema (não precisam de permissão de armazenamento)
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.analyzeFile(uri)
    }
    val pickHashList = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.importList(uri, ListKind.HASHES)
    }
    val pickDomainList = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.importList(uri, ListKind.DOMAINS)
    }
    val anyFile = arrayOf("*/*")
    val textFiles = arrayOf("text/*", "application/csv", "application/octet-stream", "*/*")

    NavigationSuiteScaffold(
        navigationSuiteItems = {
            Tab.entries.forEach { t ->
                item(
                    icon = { Icon(painterResource(t.icon), contentDescription = t.label) },
                    label = { Text(t.label) },
                    selected = t == tab,
                    onClick = { vm.selectTab(t) },
                )
            }
        },
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = { AppHeader() },
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            containerColor = MaterialTheme.colorScheme.background,
        ) { padding ->
            Box(Modifier.padding(padding)) {
                when (tab) {
                    Tab.LINKS -> LinksScreen(
                        state = links,
                        onInputChange = vm::onLinkInputChange,
                        onAnalyze = vm::analyzeLinks,
                        onClear = vm::clearLinks,
                    )
                    Tab.FILES -> FilesScreen(
                        state = files,
                        knownHashes = base.stats?.hashes,
                        onPick = { pickFile.launch(anyFile) },
                        onCancel = vm::cancelFile,
                        onClear = vm::clearFile,
                    )
                    Tab.BASE -> BaseScreen(
                        state = base,
                        onImportHashes = { pickHashList.launch(textFiles) },
                        onImportDomains = { pickDomainList.launch(textFiles) },
                        onClearImported = vm::clearImported,
                        onReloadBundled = vm::reloadBundled,
                        onDismissMessage = vm::dismissBaseMessage,
                    )
                }
            }
        }
    }
}

@Composable
private fun AppHeader() {
    Row(
        Modifier
            .fillMaxWidth()
            .statusBarsPadding()
            .padding(start = 20.dp, end = 20.dp, top = 10.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Image(
            painter = painterResource(R.drawable.klin_logo),
            contentDescription = null,
            colorFilter = ColorFilter.tint(MaterialTheme.colorScheme.onBackground),
            modifier = Modifier.size(44.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column {
            Text("Klin Kercher", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onBackground)
            Text(
                "Detetive de links e arquivos · 100% offline",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
