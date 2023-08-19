use num_bigint::{BigUint, RandBigInt};

#[derive(Debug, Clone, Default)]

/// n^x mod p
pub struct ZKP {
    pub alpha: BigUint,
    pub beta: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub rng_upper_bound: BigUint,
}

impl ZKP {
    pub fn new(
        alpha: BigUint,
        beta: BigUint,
        p: BigUint,
        q: BigUint,
        rng_upper_bound: BigUint,
    ) -> ZKP {
        ZKP {
            alpha,
            beta,
            p,
            q,
            rng_upper_bound,
        }
    }

    pub fn get_1024_bits_config() -> (BigUint, BigUint, BigUint, BigUint, BigUint) {
        let rng_upper_bound = BigUint::new(vec![u32::MAX; 4]);
        let p  = BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").expect("could not convert p from hex"));
        let q = BigUint::from_bytes_be(
            &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353")
                .expect("could not convert q from hex"),
        );
        let alpha = BigUint::from_bytes_be(&hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").expect("could not convert alpha from hex"));
        let beta = alpha.modpow(&BigUint::from(1_469_131_869u32), &p);
        (alpha, beta, p, q, rng_upper_bound)
    }

    /// output = s = k - c * x mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        let cx = c * x;
        if *k >= cx {
            // use modpow (1, q) to do mod(q)
            return (k - cx).modpow(&BigUint::from(1u32), &self.q);
        }
        self.q.clone() - (cx - k).modpow(&BigUint::from(1u32), &self.q)
    }
    /// verify that :
    ///     r1 = alpha^s * y1^c
    ///     r2 = beta^s * y2^c
    pub fn verify(
        &self,
        y1: &BigUint,
        y2: &BigUint,
        r1: &BigUint,
        r2: &BigUint,
        s: &BigUint,
        c: &BigUint,
    ) -> bool {
        let r1_verified = *r1
            == (self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);
        let r2_verified = *r2
            == (self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);

        r1_verified && r2_verified
    }

    pub fn generate_random(&self) -> BigUint {
        let mut rng = rand::thread_rng();
        rng.gen_biguint_below(&self.rng_upper_bound)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_toy_example() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let zkp = ZKP::new(
            alpha.clone(),
            beta.clone(),
            p.clone(),
            q.clone(),
            BigUint::from(1u32),
        );

        let x = BigUint::from(6u32);
        let k = BigUint::from(7u32);

        let c = BigUint::from(4u32);

        let (y1, y2) = (&alpha.modpow(&x, &p), &beta.modpow(&x, &p));
        assert_eq!(y1, &BigUint::from(2u32));
        assert_eq!(y2, &BigUint::from(3u32));
        let (r1, r2) = (&alpha.modpow(&k, &p), &beta.modpow(&k, &p));
        assert_eq!(r1, &BigUint::from(8u32));
        assert_eq!(r2, &BigUint::from(4u32));
        let s = zkp.solve(&k, &c, &x);
        assert_eq!(s, BigUint::from(5u32));
        assert!(zkp.verify(&y1, &y2, &r1, &r2, &s, &c));

        //  fake secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);

        assert!(!zkp.verify(&y1, &y2, &r1, &r2, &s_fake, &c));
    }

    #[test]
    fn test_toy_example_with_random_generator() {
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);

        let zkp = ZKP::new(alpha.clone(), beta.clone(), p.clone(), q.clone(), p.clone());

        let x = BigUint::from(6u32);
        let k = zkp.generate_random();

        let c = zkp.generate_random();

        let (y1, y2) = (&alpha.modpow(&x, &p), &beta.modpow(&x, &p));
        assert_eq!(y1, &BigUint::from(2u32));
        assert_eq!(y2, &BigUint::from(3u32));
        let (r1, r2) = (&alpha.modpow(&k, &p), &beta.modpow(&k, &p));
        let s = zkp.solve(&k, &c, &x);

        assert!(zkp.verify(&y1, &y2, &r1, &r2, &s, &c));

        //  fake secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);

        assert!(!zkp.verify(&y1, &y2, &r1, &r2, &s_fake, &c));
    }

    #[test]
    fn test_1024_bits_constants() {
        // 1024 bits
        let rng_upper_bound = BigUint::new(vec![u32::MAX; 4]);
        let p  = BigUint::from_bytes_be(&hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").expect("could not convert p from hex"));
        let q = BigUint::from_bytes_be(
            &hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353")
                .expect("could not convert q from hex"),
        );
        let alpha = BigUint::from_bytes_be(&hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").expect("could not convert alpha from hex"));

        let mut zkp = ZKP::default();
        zkp.alpha = alpha.clone();
        zkp.p = p.clone();
        zkp.q = q.clone();
        zkp.rng_upper_bound = rng_upper_bound;

        // beta can be alpha ^any number because of prime order sets properties
        let beta = alpha.modpow(&BigUint::from(zkp.generate_random()), &p);
        zkp.beta = beta.clone();
        let x = zkp.generate_random();
        let k = zkp.generate_random();

        let c = zkp.generate_random();

        let (y1, y2) = (&alpha.modpow(&x, &p), &beta.modpow(&x, &p));
        let (r1, r2) = (&alpha.modpow(&k, &p), &beta.modpow(&k, &p));
        let s = zkp.solve(&k, &c, &x);

        assert!(zkp.verify(&y1, &y2, &r1, &r2, &s, &c));

        //  fake secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);

        assert!(!zkp.verify(&y1, &y2, &r1, &r2, &s_fake, &c));
    }

    #[test]
    fn test_2048_bits_constants() {
        // 2048  bits
        let rng_upper_bound = BigUint::new(vec![u32::MAX; 8]);
        let p  = BigUint::from_bytes_be(&hex::decode("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F").expect("could not convert p from hex"));
        let q = BigUint::from_bytes_be(
            &hex::decode("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB")
                .expect("could not convert q from hex"),
        );

        let alpha = BigUint::from_bytes_be(&hex::decode("AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA").expect("could not convert alpha from hex"));

        let mut zkp = ZKP::default();
        zkp.alpha = alpha.clone();
        zkp.p = p.clone();
        zkp.q = q.clone();
        zkp.rng_upper_bound = rng_upper_bound;

        // beta can be alpha ^any number because of prime order sets properties
        let beta = alpha.modpow(&BigUint::from(zkp.generate_random()), &p);

        zkp.beta = beta.clone();
        let x = zkp.generate_random();
        let k = zkp.generate_random();

        let c = zkp.generate_random();

        let (y1, y2) = (&alpha.modpow(&x, &p), &beta.modpow(&x, &p));
        let (r1, r2) = (&alpha.modpow(&k, &p), &beta.modpow(&k, &p));
        let s = zkp.solve(&k, &c, &x);

        assert!(zkp.verify(&y1, &y2, &r1, &r2, &s, &c));

        //  fake secret
        let x_fake = BigUint::from(7u32);
        let s_fake = zkp.solve(&k, &c, &x_fake);

        assert!(!zkp.verify(&y1, &y2, &r1, &r2, &s_fake, &c));
    }
}
