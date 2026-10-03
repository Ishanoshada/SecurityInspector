package com.ishanoshada.securityinspector

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ishanoshada.securityinspector.flags.FlagCategory
import com.ishanoshada.securityinspector.flags.FlagChallengeDialog
import com.ishanoshada.securityinspector.flags.FlagSolverDialog
import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import com.ishanoshada.securityinspector.ui.theme.SentinelXTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface UiState {
    object Loading : UiState
    data class Success(
        val securityCategories: List<SecurityCategory>,
        val flagCategory: SecurityCategory,
    ) : UiState
    data class Error(val message: String) : UiState
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SentinelXTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    SecurityDashboardScreen(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                    )
                }
            }
        }
    }
}

@Composable
fun SecurityDashboardScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current.applicationContext
    var uiState by remember { mutableStateOf<UiState>(UiState.Loading) }
    var selectedCheckItem by remember { mutableStateOf<SecurityCheckItem?>(null) }
    var solverTarget by remember { mutableStateOf<SecurityCheckItem?>(null) }
    var selectedTab by remember { mutableStateOf(0) } // 0 = Security Checks, 1 = CTF Flags Lab
    val scope = rememberCoroutineScope()

    fun loadData() {
        uiState = UiState.Loading
        scope.launch {
            try {
                val securityChecks = withContext(Dispatchers.IO) {
                    SecurityChecker.runAllChecks(context)
                }
                val flagCheck = withContext(Dispatchers.IO) {
                    FlagCategory.getFlagChecks()
                }
                uiState = UiState.Success(
                    securityCategories = securityChecks,
                    flagCategory = flagCheck
                )
            } catch (e: Exception) {
                uiState = UiState.Error(e.localizedMessage ?: "Failed to perform security checks")
            }
        }
    }

    LaunchedEffect(Unit) {
        loadData()
    }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        val screenWidth = maxWidth
        val isTabletOrLandscape = screenWidth >= 600.dp

        when (val state = uiState) {
            is UiState.Loading -> {
                SimpleLoadingScreen()
            }

            is UiState.Error -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = "⚠️ Inspection Error",
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = state.message,
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    Button(onClick = { loadData() }) {
                        Text("Retry")
                    }
                }
            }

            is UiState.Success -> {
                val scrollState = rememberScrollState()

                // Calculate stats based on active tab
                val currentItems = if (selectedTab == 0) {
                    state.securityCategories.flatMap { it.items }
                } else {
                    state.flagCategory.items
                }
                val totalChecks = currentItems.size
                val totalDetected = currentItems.count { it.isDetected }
                val totalClean = totalChecks - totalDetected

                val contentModifier = if (isTabletOrLandscape) {
                    Modifier
                        .fillMaxSize()
                        .widthIn(max = 720.dp)
                        .verticalScroll(scrollState)
                        .padding(horizontal = 24.dp, vertical = 16.dp)
                } else {
                    Modifier
                        .fillMaxSize()
                        .verticalScroll(scrollState)
                        .padding(horizontal = 16.dp, vertical = 16.dp)
                }

                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.TopCenter
                ) {
                    // Main Scrollable Content
                    Column(
                        modifier = contentModifier,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        // Header Title
                        Text(
                            text = "SentinelX Security",
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )

                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Tap any check row to view deep code & API details",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.7f)
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        // Top Section Switcher Tabs
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { selectedTab = 0 },
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedTab == 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                                    contentColor = if (selectedTab == 0) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
                                ),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("🛡️ Security Checks", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }

                            Button(
                                onClick = { selectedTab = 1 },
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedTab == 1) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                                    contentColor = if (selectedTab == 1) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
                                ),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("🚩 CTF Flags Lab", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                        }

                        Spacer(modifier = Modifier.height(16.dp))

                        if (selectedTab == 0) {
                            // About / GitHub Card
                            GitHubAboutCard()

                            Spacer(modifier = Modifier.height(20.dp))

                            // Section Title
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Start
                            ) {
                                Text(
                                    text = "Detailed Check Results",
                                    style = MaterialTheme.typography.titleLarge,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                            }

                            Spacer(modifier = Modifier.height(12.dp))

                            // Security Categories List Cards
                            state.securityCategories.forEach { category ->
                                SecurityCategoryCard(
                                    category = category,
                                    onItemClick = { item -> selectedCheckItem = item }
                                )
                                Spacer(modifier = Modifier.height(16.dp))
                            }
                        } else {
                            // CTF Flags Lab Section
                            CtfBannerCard()

                            Spacer(modifier = Modifier.height(20.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Start
                            ) {
                                Text(
                                    text = "CTF Challenges",
                                    style = MaterialTheme.typography.titleLarge,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onBackground
                                )
                            }

                            Spacer(modifier = Modifier.height(12.dp))

                            SecurityCategoryCard(
                                category = state.flagCategory,
                                onItemClick = { item -> selectedCheckItem = item }
                            )
                            Spacer(modifier = Modifier.height(16.dp))
                        }

                        // Extra bottom spacer to ensure content isn't covered by floating elements
                        Spacer(modifier = Modifier.height(160.dp))
                    }
                }

                // Fixed Bottom Floating Summary Bar (adapts max width on tablets)
                FloatingSummaryBar(
                    totalChecks = totalChecks,
                    totalDetected = totalDetected,
                    totalClean = totalClean,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .widthIn(max = 640.dp)
                        .padding(horizontal = 16.dp, vertical = 16.dp)
                )

                // Floating Circular Refresh FAB on Bottom Right Side (positioned above summary bar, white background, zero overlap)
                FloatingActionButton(
                    onClick = { loadData() },
                    shape = CircleShape,
                    containerColor = Color.White,
                    contentColor = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .align(Alignment.BottomEnd)
                        .padding(bottom = 84.dp, end = if (isTabletOrLandscape) 32.dp else 20.dp)
                ) {
                    Text(text = "🔄", fontSize = 22.sp)
                }
            }
        }

        // Popup detail dialog when an item is clicked
        selectedCheckItem?.let { item ->
            if (item.id.startsWith("flag_")) {
                FlagChallengeDialog(
                    item = item,
                    onDismiss = { selectedCheckItem = null },
                    onLaunchSolver = {
                        selectedCheckItem = null
                        solverTarget = item
                    }
                )
            } else {
                CheckDetailDialog(
                    item = item,
                    onDismiss = { selectedCheckItem = null }
                )
            }
        }

        // Auto-Solver Dialog for CTF Flags
        solverTarget?.let { item ->
            FlagSolverDialog(
                flagId = item.id,
                flagTitle = item.name,
                onDismiss = { solverTarget = null }
            )
        }
    }
}

@Composable
fun SimpleLoadingScreen() {
    var currentCount by remember { mutableStateOf(1) }
    LaunchedEffect(Unit) {
        for (i in 1..65 step 3) {
            delay(30)
            currentCount = i.coerceAtMost(65)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        CircularProgressIndicator(
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(48.dp),
            strokeWidth = 4.dp
        )

        Spacer(modifier = Modifier.height(24.dp))

        Text(
            text = "SentinelX Security Inspector",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Checking security rules: $currentCount / 65",
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.primary
        )

        Spacer(modifier = Modifier.height(16.dp))

        LinearProgressIndicator(
            progress = { currentCount / 65f },
            modifier = Modifier
                .fillMaxWidth(0.6f)
                .height(6.dp),
            color = MaterialTheme.colorScheme.primary,
            trackColor = MaterialTheme.colorScheme.surfaceVariant
        )
    }
}

@Composable
fun CtfBannerCard() {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 4.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "🏴 SentinelX CTF Lab",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Learn static reversing (jadx) and dynamic instrumentation (Frida) step-by-step. Tap any challenge below to view hints, submit your guessed flag, or launch the Auto-Solver lab!",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.85f),
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun GitHubAboutCard() {
    val context = LocalContext.current
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 4.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Text(text = "🛡️ ", fontSize = 20.sp)
                Text(
                    text = "About SecurityInspector",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Open-source Android RASP & Environment Inspection Tool detecting Frida, Root, LSPosed, Debuggers, Emulators, & Tampering.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f),
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                Button(
                    onClick = {
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/ishanoshada/SecurityInspector"))
                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                        } catch (_: Exception) {}
                    }
                ) {
                    Text("GitHub Repo", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }

                Button(
                    onClick = {
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://ishanoshada.com"))
                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                        } catch (_: Exception) {}
                    }
                ) {
                    Text("@ishanoshada", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
fun FloatingSummaryBar(
    totalChecks: Int,
    totalDetected: Int,
    totalClean: Int,
    modifier: Modifier = Modifier
) {
    ElevatedCard(
        modifier = modifier.fillMaxWidth(0.92f),
        shape = RoundedCornerShape(28.dp),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 12.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            FloatingSummaryItem(
                label = "Total Checks",
                value = totalChecks.toString(),
                color = MaterialTheme.colorScheme.onSurface
            )

            HorizontalDivider(
                modifier = Modifier
                    .height(30.dp)
                    .width(1.dp),
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.2f)
            )

            FloatingSummaryItem(
                label = "Detected (True)",
                value = totalDetected.toString(),
                color = if (totalDetected > 0) Color(0xFFD32F2F) else Color(0xFF388E3C)
            )

            HorizontalDivider(
                modifier = Modifier
                    .height(30.dp)
                    .width(1.dp),
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.2f)
            )

            FloatingSummaryItem(
                label = "Clean (False)",
                value = totalClean.toString(),
                color = Color(0xFF388E3C)
            )
        }
    }
}

@Composable
fun FloatingSummaryItem(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            fontSize = 20.sp,
            fontWeight = FontWeight.ExtraBold,
            color = color
        )
        Text(
            text = label,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
    }
}

@Composable
fun CheckDetailDialog(item: SecurityCheckItem, onDismiss: () -> Unit) {
    val scrollState = rememberScrollState()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Column {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = item.name,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))

                    val badgeBg = if (item.isDetected) Color(0xFFFFEBEE) else Color(0xFFE8F5E9)
                    val badgeText = if (item.isDetected) "TRUE" else "FALSE"
                    val badgeTextColor = if (item.isDetected) Color(0xFFC62828) else Color(0xFF2E7D32)

                    Surface(
                        color = badgeBg,
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            text = badgeText,
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 12.sp,
                            color = badgeTextColor,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = item.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                )
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(scrollState)
            ) {
                HorizontalDivider(color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.15f))
                Spacer(modifier = Modifier.height(12.dp))

                // Function Name
                DetailLabel(label = "Function Called")
                Text(
                    text = item.functionName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )

                Spacer(modifier = Modifier.height(12.dp))

                // APIs & Methods
                DetailLabel(label = "APIs / Files / Methods Inspected")
                item.methodsAndApis.forEach { api ->
                    Text(
                        text = "• $api",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Technical Explanation
                DetailLabel(label = "Deep Technical Explanation")
                Text(
                    text = item.technicalExplanation,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )

                Spacer(modifier = Modifier.height(14.dp))

                // Code Snippet
                DetailLabel(label = "Kotlin Check Implementation Code")
                Spacer(modifier = Modifier.height(4.dp))
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = item.exampleCode,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close", fontWeight = FontWeight.Bold)
            }
        }
    )
}

@Composable
fun DetailLabel(label: String) {
    Text(
        text = label,
        style = MaterialTheme.typography.labelMedium,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary
    )
}

@Composable
fun SecurityCategoryCard(category: SecurityCategory, onItemClick: (SecurityCheckItem) -> Unit) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 4.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = category.iconEmoji, fontSize = 22.sp)
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = category.categoryName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.1f))
            Spacer(modifier = Modifier.height(12.dp))

            category.items.forEachIndexed { index, item ->
                SecurityCheckRow(item = item, onClick = { onItemClick(item) })
                if (index < category.items.size - 1) {
                    Spacer(modifier = Modifier.height(10.dp))
                }
            }
        }
    }
}

@Composable
fun SecurityCheckRow(item: SecurityCheckItem, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.name,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = item.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        val badgeBg = if (item.isDetected) Color(0xFFFFEBEE) else Color(0xFFE8F5E9)
        val badgeText = if (item.isDetected) "TRUE" else "FALSE"
        val badgeTextColor = if (item.isDetected) Color(0xFFC62828) else Color(0xFF2E7D32)

        Surface(
            color = badgeBg,
            shape = RoundedCornerShape(8.dp)
        ) {
            Text(
                text = badgeText,
                fontWeight = FontWeight.ExtraBold,
                fontSize = 12.sp,
                color = badgeTextColor,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun DashboardPreview() {
    SentinelXTheme {
        SecurityDashboardScreen()
    }
}
