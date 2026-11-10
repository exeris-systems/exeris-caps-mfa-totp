package eu.exeris.caps.mfatotp;

import eu.exeris.kernel.spi.contract.EntitlementClass;
import eu.exeris.kernel.spi.contract.EntitlementRequirement;
import eu.exeris.kernel.tck.contract.AbstractEntitlementRequirementTck;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.ServiceLoader;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("exeris-caps-mfa-totp: EntitlementRequirement")
class MfaTotpEntitlementTest extends AbstractEntitlementRequirementTck {

    @Override
    protected Class<? extends EntitlementRequirement> providerClass() {
        return MfaTotpEntitlement.class;
    }

    @Test
    @DisplayName("ServiceLoader discovers the provider from the cap's own service registration")
    void serviceLoaderDiscoversTheProvider() {
        List<Class<? extends EntitlementRequirement>> types = ServiceLoader.load(EntitlementRequirement.class)
                .stream()
                .map(ServiceLoader.Provider::type)
                .toList();

        assertThat(types).contains(MfaTotpEntitlement.class);
    }

    @Test
    @DisplayName("It requires exactly this cap's own capability identifier")
    void requiresOnlyItsOwnCapability() {
        assertThat(new MfaTotpEntitlement().requiredCapabilities()).containsExactly("exeris-caps-mfa-totp");
        assertThat(MfaTotpEntitlement.CAPABILITY_ID).isEqualTo("exeris-caps-mfa-totp");
    }

    @Test
    @DisplayName("entitlementClass() is COMMERCIAL and stable across calls")
    void entitlementClassIsCommercialAndStable() {
        MfaTotpEntitlement entitlement = new MfaTotpEntitlement();
        assertThat(entitlement.entitlementClass()).isEqualTo(EntitlementClass.COMMERCIAL);
        assertThat(entitlement.entitlementClass()).isSameAs(entitlement.entitlementClass());
    }
}
