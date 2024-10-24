pub mod capability;
pub mod client;
pub mod event;
pub mod gcc;
pub mod global;
pub mod license;
pub mod mcs;
pub mod per;
pub mod sec;
pub mod tpkt;
pub mod x224;

/// LicenseStore provides the ability to save (and later retrieve)
/// RDS licenses.
pub trait LicenseStore {
    fn write_license(
        &mut self,
        major: u16,
        minor: u16,
        company: &str,
        issuer: &str,
        product_id: &str,
        license: &[u8],
    );
    fn read_license(
        &self,
        major: u16,
        minor: u16,
        company: &str,
        issuer: &str,
        product_id: &str,
    ) -> Option<Vec<u8>>;
}

impl<L: LicenseStore + ?Sized> LicenseStore for &mut L {
    fn write_license(
        &mut self,
        major: u16,
        minor: u16,
        company: &str,
        issuer: &str,
        product_id: &str,
        license: &[u8],
    ) {
        (**self).write_license(major, minor, company, issuer, product_id, license)
    }

    fn read_license(
        &self,
        major: u16,
        minor: u16,
        company: &str,
        issuer: &str,
        product_id: &str,
    ) -> Option<Vec<u8>> {
        (**self).read_license(major, minor, company, issuer, product_id)
    }
}

impl<T: LicenseStore + ?Sized> LicenseStore for Box<T> {
    fn write_license(
        &mut self,
        major: u16,
        minor: u16,
        company: &str,
        issuer: &str,
        product_id: &str,
        license: &[u8],
    ) {
        (**self).write_license(major, minor, company, issuer, product_id, license)
    }
    fn read_license(
        &self,
        major: u16,
        minor: u16,
        company: &str,
        issuer: &str,
        product_id: &str,
    ) -> Option<Vec<u8>> {
        (**self).read_license(major, minor, company, issuer, product_id)
    }
}
