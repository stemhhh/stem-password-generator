using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace StemPasswordGenerator.Tests;

public sealed class LocalizationTests
{
    [Fact]
    public void EnglishAndSpanish_AreDifferentForCoreUi()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.English);
            var english = UiStrings.Get("NavVault");
            UiStrings.SetLanguage(AppLanguage.Spanish);
            var spanish = UiStrings.Get("NavVault");

            Assert.Equal("Vault", english);
            Assert.Equal("Bóveda", spanish);
            Assert.Equal("Ajustes", UiStrings.Get("NavSettings"));
            Assert.Equal("Acerca de", UiStrings.Get("NavAbout"));
            Assert.Contains("forense", UiStrings.Get("WarnPanicForensics"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Ctrl+Alt+S", UiStrings.Get("GlobalHotkeys"), StringComparison.Ordinal);
            Assert.Equal("Suelta para sellar", UiStrings.Get("DropToSealTitle"));
            Assert.Equal("Contraseñas anteriores", UiStrings.Get("PasswordHistory"));
            Assert.Equal("Códigos de recuperación", UiStrings.Get("KindRecoveryLong"));
            Assert.Equal("API, SSH o .env", UiStrings.Get("KindSecretLong"));
            Assert.Contains("texto plano", UiStrings.Get("CsvImportWarning"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("texto plano", UiStrings.Get("CsvExportConfirmBody"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("otro PC", UiStrings.Get("PortableExportButton"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("tarjetas Shamir", UiStrings.Get("ShamirPrintHint"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Se acabó", UiStrings.Get("StudentMasterForget"), StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Por qué esto es fuerte", UiStrings.Get("StudentWhyTitle"));
            Assert.Equal("Llave USB", UiStrings.Get("NavUsb"));
            Assert.Equal("Borrar todos los datos de Stem…", UiStrings.Get("ResetAppButton"));
            Assert.Equal("Baúl multimedia", UiStrings.Get("NavVaultMedia"));
            Assert.Equal("Cifrar", UiStrings.Get("NavCipher"));
            Assert.Equal("Bloqueado", UiStrings.Get("VaultStatusLocked"));
            Assert.Equal("Desbloqueado", UiStrings.Get("VaultStatusUnlocked"));
            Assert.Equal("Fotos", UiStrings.Get("MediaGalleryPhotos"));
            Assert.Equal("Registros", UiStrings.Get("NavVaultActivity"));
            Assert.Contains("maestra", UiStrings.Get("AuditHint"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Registros", UiStrings.Get("AboutToolVaultBody"), StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Todas las carpetas", UiStrings.Get("FolderAll"));
            Assert.Contains("1 año", UiStrings.Get("HealthPasswordOverdue"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("7 palabras", UiStrings.Get("RecoveryPhraseOnceBody"), StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Olvidé la contraseña maestra", UiStrings.Get("ForgotMaster"));
            Assert.Contains("QWERTY", UiStrings.Get("MasterKeyboardHint"), StringComparison.Ordinal);
            Assert.Equal("Cambiar contraseña maestra", UiStrings.Get("ChangeMasterButton"));
            Assert.Contains("FIDO2", UiStrings.Get("UsbNotFidoBody"), StringComparison.Ordinal);
            Assert.NotEqual(english, spanish);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }

    [Fact]
    public void SpanishGuidance_KeepsTheSecurityWarning()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.Spanish);
            Assert.Contains("contraseña maestra", SharedPcGuidance.NamesAreVisible, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Windows Hello", SharedPcGuidance.HelloCannotTellPeopleApart, StringComparison.Ordinal);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }

    [Fact]
    public void Catalog_HasMatchingPlaceholdersAndNoMissingKeys()
    {
        try
        {
            foreach (var (key, english, spanish) in UiStrings.Snapshot())
            {
                Assert.False(string.IsNullOrWhiteSpace(english), key);
                Assert.False(string.IsNullOrWhiteSpace(spanish), key);
                Assert.Equal(PlaceholderIndexes(english), PlaceholderIndexes(spanish));

                UiStrings.SetLanguage(AppLanguage.English);
                Assert.Equal(english, UiStrings.Get(key));
                UiStrings.SetLanguage(AppLanguage.Spanish);
                Assert.Equal(spanish, UiStrings.Get(key));
            }

            UiStrings.SetLanguage(AppLanguage.Spanish);
            Assert.Equal("Nuevo inicio de sesión", UiStrings.Get("NewLogin"));
            Assert.Equal("Preguntas frecuentes", UiStrings.Get("AboutFaqTitle"));
            Assert.Equal("Tutoriales", UiStrings.Get("AboutGuidesTitle"));
            Assert.Contains("baúl", UiStrings.Get("AboutToolVaultBody"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("k-anonimato", UiStrings.Get("AboutFaqCheckA"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Type-1", UiStrings.Get("AboutFaqCipherA"), StringComparison.Ordinal);
            Assert.Contains("MFA", UiStrings.Get("AboutFaqHumanA"), StringComparison.Ordinal);
            Assert.Contains("FIDO2", UiStrings.Get("AboutToolUsbBody"), StringComparison.Ordinal);
            Assert.Contains("no hay cuenta", UiStrings.Get("AboutBody1"), StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Mi bóveda", UiStrings.Get("MyVault"));
            Assert.DoesNotContain("solo mira reutilizadas", UiStrings.Get("HealthNone"), StringComparison.Ordinal);
            Assert.DoesNotContain("{0}", UiStrings.Format("VaultCreated", "Alex"), StringComparison.Ordinal);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }

    private static string PlaceholderIndexes(string text)
    {
        var matches = System.Text.RegularExpressions.Regex.Matches(text, "\\{[0-9]+\\}");
        return string.Join(",", matches.Select(static match => match.Value).Distinct().OrderBy(static value => value, StringComparer.Ordinal));
    }
}
