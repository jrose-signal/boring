use crate::foreign_types::ForeignTypeRef;
use crate::hash::{DigestBytes, MessageDigest};
use crate::pkey::{HasPublic, PKeyRef};
use crate::stack::{StackRef, Stackable};
use crate::x509::Asn1BitStringRef;
use crate::x509::Asn1IntegerRef;
use crate::x509::Asn1TimeRef;
use crate::x509::X509AlgorithmRef;
use crate::x509::X509Extension;
use crate::x509::X509NameRef;
use crate::{cvt, cvt_n, cvt_p, ErrorStack};
use std::convert::TryInto;
use std::fmt::Formatter;
use std::{fmt, ptr};

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_REVOKED;
    fn drop = ffi::X509_REVOKED_free;

    /// A builder type used to construct an `X509_REVOKED`.
    pub struct X509Revoked;
}

impl Stackable for X509Revoked {
    type StackType = ffi::stack_st_X509_REVOKED;
}

impl X509RevokedRef {
    /// Returns the serial number of the revoked certificate
    ///
    /// This corresponds to [`X509_REVOKED_get0_serialNumber`].
    ///
    /// [`X509_REVOKED_get0_serialNumber`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_get0_serialNumber.html
    pub fn serial_number(&self) -> &Asn1IntegerRef {
        unsafe {
            let r = ffi::X509_REVOKED_get0_serialNumber(self.as_ptr());
            assert!(!r.is_null());
            Asn1IntegerRef::from_ptr(r as *mut _)
        }
    }

    /// Returns certificate's revocation date
    ///
    /// This corresponds to [`X509_REVOKED_get0_revocationDate`].
    ///
    /// [`X509_REVOKED_get0_revocationDate`]: https://www.openssl.org/docs/man1.1.1/man3/X509_REVOKED_get0_revocationDate
    pub fn revocation_date(&self) -> &Asn1TimeRef {
        unsafe {
            let date = ffi::X509_REVOKED_get0_revocationDate(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date as *mut _)
        }
    }
}

impl fmt::Debug for X509RevokedRef {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        let sn = self
            .serial_number()
            .to_bn()
            .and_then(|bn| bn.to_hex_str())
            .map(|hex| hex.to_string())
            .unwrap_or_else(|_| "".to_owned());

        fmt.debug_struct("X509Revoked")
            .field("serial_number", &sn)
            .field("revocation_date", self.revocation_date())
            .finish()
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_CRL;
    fn drop = ffi::X509_CRL_free;

    /// A builder type used to construct an `X509CRL`.
    pub struct X509CRL;
}

impl Stackable for X509CRL {
    type StackType = ffi::stack_st_X509_CRL;
}

impl X509CRL {
    from_pem! {
        from_pem,
        X509CRL,
        ffi::PEM_read_bio_X509_CRL
    }

    from_der! {
       /// Deserializes a DER-encoded X509 structure.
       ///
       /// This corresponds to [`d2i_X509`].
       ///
       /// [`d2i_X509`]: https://www.openssl.org/docs/manmaster/man3/d2i_X509.html
        from_der,
        X509CRL,
        ffi::d2i_X509_CRL,
        ::libc::c_long
    }
}

impl X509CRLRef {
    pub fn last_update(&self) -> &Asn1TimeRef {
        unsafe {
            let date = ffi::X509_CRL_get0_lastUpdate(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date as *mut _)
        }
    }

    pub fn next_update(&self) -> &Asn1TimeRef {
        unsafe {
            let date = ffi::X509_CRL_get0_nextUpdate(self.as_ptr());
            assert!(!date.is_null());
            Asn1TimeRef::from_ptr(date as *mut _)
        }
    }

    pub fn issuer(&self) -> &X509NameRef {
        unsafe {
            let name = ffi::X509_CRL_get_issuer(self.as_ptr());
            assert!(!name.is_null());
            X509NameRef::from_ptr(name)
        }
    }

    pub fn extensions(&self) -> Option<&StackRef<X509Extension>> {
        unsafe {
            let extensions = ffi::X509_CRL_get0_extensions(self.as_ptr());
            if extensions.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(extensions as *mut _))
            }
        }
    }

    pub fn revoked(&self) -> Result<&StackRef<X509Revoked>, ErrorStack> {
        unsafe {
            let revoked = cvt_p(ffi::X509_CRL_get_REVOKED(self.as_ptr()))?;
            Ok(StackRef::from_ptr(revoked))
        }
    }

    pub fn signature(&self) -> &Asn1BitStringRef {
        unsafe {
            let mut signature = ptr::null();
            ffi::X509_CRL_get0_signature(self.as_ptr(), &mut signature, ptr::null_mut());
            assert!(!signature.is_null());
            Asn1BitStringRef::from_ptr(signature as *mut _)
        }
    }

    pub fn signature_algorithm(&self) -> &X509AlgorithmRef {
        unsafe {
            let mut algor = ptr::null();
            ffi::X509_CRL_get0_signature(self.as_ptr(), ptr::null_mut(), &mut algor);
            assert!(!algor.is_null());
            X509AlgorithmRef::from_ptr(algor as *mut _)
        }
    }

    pub fn digest(&self, hash_type: MessageDigest) -> Result<DigestBytes, ErrorStack> {
        unsafe {
            let mut digest = DigestBytes {
                buf: [0; ffi::EVP_MAX_MD_SIZE as usize],
                len: ffi::EVP_MAX_MD_SIZE as usize,
            };
            let mut len = ffi::EVP_MAX_MD_SIZE.try_into().unwrap();
            cvt(ffi::X509_CRL_digest(
                self.as_ptr(),
                hash_type.as_ptr(),
                digest.buf.as_mut_ptr() as *mut _,
                &mut len,
            ))?;
            digest.len = len as usize;

            Ok(digest)
        }
    }

    pub fn verify<T>(&self, key: &PKeyRef<T>) -> Result<bool, ErrorStack>
    where
        T: HasPublic,
    {
        unsafe { cvt_n(ffi::X509_CRL_verify(self.as_ptr(), key.as_ptr())).map(|n| n != 0) }
    }

    to_pem! {
        to_pem,
        ffi::PEM_write_bio_X509_CRL
    }

    to_der! {
        to_der,
        ffi::i2d_X509_CRL
    }
}

impl fmt::Debug for X509CRL {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_struct = formatter.debug_struct("X509CRL");
        debug_struct.field("last_update", self.last_update());
        debug_struct.field("next_update", self.next_update());
        debug_struct.field("issuer", self.issuer());
        debug_struct.field("signature_algorithm", &self.signature_algorithm().object());
        if let Ok(revoked) = self.revoked() {
            debug_struct.field("revoked", &revoked);
        }
        if let Some(extensions) = self.extensions() {
            debug_struct.field("extensions", &extensions);
        }
        debug_struct.finish()
    }
}
