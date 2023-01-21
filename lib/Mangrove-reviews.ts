import {Metadata, Review} from "./Review";
import jwkToPem from "jwk-to-pem"
import axios from "axios";
import {SignJWT} from "jose"
import {JWTPayload} from "jose/dist/types/types";

export interface QueryParameters {
    /**
     * Search for reviews that have this string in `sub` or `opinion` field.
     */
    q?: string,
    /**
     * Search for review with this `signature` value.
     */
    signature?: string

    /**
     *  Reviews by issuer with the following PEM public key.
     */
    kid?: string
    /**
     *  Reviews issued at this UNIX time.
     */
    iat?: number
    /**
     *  Reviews with UNIX timestamp greater than this.
     */
    gt_iat?: number
    /**
     *  Reviews of the given subject URI.
     */
    sub?: string
    /**
     *  Reviews with the given rating.
     */
    rating?: number
    /**
     *  Reviews with the given opinion.
     */
    opinion?: string
    /**
     *  Maximum number of reviews to be returned.
     */
    limit?: number
    /**
     *  Get only reviews with opinion text.
     */
    opinionated?: boolean
    /**
     *  Include reviews of example subjects.
     */
    examples?: boolean
    /**
     *  Include aggregate information about review issuers.
     */
    issuers?: boolean
    /**
     *  Include aggregate information about reviews of returned reviews.
     */
    maresi_subjects?: boolean

}

export class MangroveReviews {
    /** The API of the server used for https://mangrove.reviews */
    public static readonly ORIGINAL_API = 'https://api.mangrove.reviews'
    private static readonly PRIVATE_KEY_METADATA = 'Mangrove private key'

    /** Assembles JWT from base payload, mutates the payload as needed.
     * @param keypair - WebCrypto keypair, can be generated with `generateKeypair`.
     * @param {Payload} payload - Base {@link Payload} to be cleaned, it will be mutated.
     * @returns {string} Mangrove Review encoded as JWT.
     */
    public static async signReview(keypair: CryptoKeyPair, payload: Review): Promise<string> {
        payload = MangroveReviews.cleanPayload(payload)
        const algo = 'ES256'
        const kid = await MangroveReviews.publicToPem(keypair.publicKey)
        const jwk = JSON.stringify(await crypto.subtle.exportKey('jwk', keypair.publicKey))
        return await new SignJWT(<JWTPayload>payload)
            .setProtectedHeader({
                alg: algo,
                kid,
                jwk: <any> jwk,
                enc: "utf-8"
            })
            .sign(keypair.privateKey);
    }

    /**
     * Submit a signed review to be stored in the database.
     * @param {string} jwt Signed review in JWT format.
     * @param {string} [api=ORIGINAL_API] API endpoint used to fetch the data.
     * @returns {Promise} Resolves to "true" in case of successful insertion or rejects with errors.
     */
    public static submitReview(jwt: string, api: string = MangroveReviews.ORIGINAL_API) {
        return axios.put(`${api}/submit/${jwt}`)
    }

    /**
     * Composition of `signReview` and `submitReview`.
     * @param keypair WebCrypto keypair, can be generated with `generateKeypair`.
     * @param {Payload} payload Base {@link Payload} to be cleaned, it will be mutated.
     * @param {string} [api=ORIGINAL_API] - API endpoint used to fetch the data.
     */
    static async signAndSubmitReview(keypair: CryptoKeyPair, payload: Review, api: string = MangroveReviews.ORIGINAL_API) {
        const jwt = await MangroveReviews.signReview(keypair, payload)
        return MangroveReviews.submitReview(jwt, api)
    }

    /**
     * Retrieve reviews which fulfill the query.
     * @param {QueryParameters} query Query to be passed to API, see the API documentation for examples.

     * @param api The api-endpoint to query; default: mangrove.reviews
     */
    public static async getReviews(query: QueryParameters, api = MangroveReviews.ORIGINAL_API):
        Promise<{
            /** A list of reviews satisfying the query.*/
            reviews: {
                signature: string,
                jwt: string,
                kid: string,
                payload: Review,
                scheme: "geo" | string
            }[],
            /**  A map from Review identifiers (urn:maresi:<signature>) to information about the reviews of that review. */
            maresi_subjects?: any[],
            issuers?: any[]
        }> {
        const {data} = await axios.get(`${api}/reviews`, {
            params: query,
            headers: {'Content-Type': 'application/json'}
        })
        return data
    }

    /**
     * Get aggregate information about the review subject.
     * @param {string} uri URI of the review subject.
     * @param {string} [api=ORIGINAL_API] API endpoint used to fetch the data.
     */
    public static getSubject(uri: string, api = MangroveReviews.ORIGINAL_API) {
        return axios.get(`${api}/subject/${encodeURIComponent(uri)}`).then(({data}) => data)
    }

    /**
     * Get aggregate information about the reviewer.
     * @param {string} pem - Reviewer public key in PEM format.
     * @param {string} [api=ORIGINAL_API] - API endpoint used to fetch the data.
     */
    public static getIssuer(pem: string, api = MangroveReviews.ORIGINAL_API) {
        return axios.get(`${api}/issuer/${encodeURIComponent(pem)}`).then(({data}) => data)
    }

    /**
     * Retrieve aggregates for multiple subjects or issuers.
     * @param {Object} query Batch query listing identifiers to use for fetching.
     * @param {string[]} [query.subs] A list of subject URIs to get aggregates for.
     * @param {string[]} [query.pems] A list of issuer PEM public keys to get aggregates for.
     * @param {string} [api=ORIGINAL_API] - API endpoint used to fetch the data.
     */
    public static batchAggregate(query: { subs?: string[], pems?: string[] }, api = MangroveReviews.ORIGINAL_API):
        null |
        Promise<{
            "issuers": Record<string, { count: number, neutrality: number }>,
            "subjects": Record<string, {
                "confirmed_count": number,
                "count": number,
                "opinion_count": number,
                "positive_count": NamedNodeMap,
                "quality": number,
                "sub": string
            }>
        }> {
        if (!query.pems && !query.subs) {
            return null
        }
        return axios.post(`${api}/batch`, query).then(({data}) => data)
    }

    /**
     * Generate a new user identity, which can be used for signing reviews and stored for later.
     * @returns ECDSA
     * [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
     * key pair with `privateKey` and `publicKey`
     */
    public static generateKeypair(): Promise<CryptoKeyPair> {
        return crypto.subtle
            .generateKey(
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                true,
                ['sign', 'verify']
            )
    }

    /**
     * Come back from JWK representation to representation which allows for signing.
     * Import keys which were exported with `keypairToJwk`.
     * @param jwk - Private JSON Web Key (JWK) to be converted in to a WebCrypto keypair.
     */
    public static async jwkToKeypair(jwk: JsonWebKey & {metadata: string} ) {
        // Do not mutate the argument.
        let key = {...jwk}
        if (!key || key.metadata !== MangroveReviews.PRIVATE_KEY_METADATA) {
            throw new Error(
                `does not contain the required metadata field "${MangroveReviews.PRIVATE_KEY_METADATA}"`
            )
        }
        const sk = await crypto.subtle.importKey(
            'jwk',
            key,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign']
        )
        delete key.d
        delete key.dp
        delete key.dq
        delete key.q
        delete key.qi
        key.key_ops = ['verify']
        const pk = await crypto.subtle.importKey(
            'jwk',
            key,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['verify']
        )
        return {privateKey: sk, publicKey: pk}
    }

    /**
     * Exports a keypair to JSON Web Key (JWK) of the private key.
     * JWK is a format which can be then used to stringify and store.
     * You can later import it back with `jwkToKeypair`.
     * @param keypair - WebCrypto key pair, can be generate with `generateKeypair`.
     */
    public static async keypairToJwk(keypair: CryptoKeyPair) {
        const s = await crypto.subtle.exportKey('jwk', keypair.privateKey)
        s["metadata"] = MangroveReviews.PRIVATE_KEY_METADATA
        return s
    }

    public static u8aToString(buf: ArrayBuffer): string {
        return new TextDecoder().decode(buf);
        //return String.fromCharCode.apply(null, new Uint8Array(buf))
    }

    /**
     * Get PEM represenation of the user "password".
     * @param key - Private WebCrypto key to be exported.
     */
    public static async privateToPem(key: CryptoKey) {
        try {
            const exported: ArrayBuffer = await crypto.subtle.exportKey('pkcs8', key)
            const exportedAsBase64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
            return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`
        } catch {
            // Workaround for Firefox webcrypto not working.
            const exported: JsonWebKey = await crypto.subtle.exportKey('jwk', key)
            return jwkToPem(<any> exported, {private: true})
        }
    }

    /**
     * Get PEM representation of public reviewer identity.
     * This format can be found in the `kid` field of a Mangrove Review Header.
     * @param key - Public WebCrypto key to be exported.
     */
    public static async publicToPem(key: CryptoKey): Promise<string> {
        const exported: ArrayBuffer = await crypto.subtle.exportKey('spki', key)
        const exportedAsBase64 = btoa(String.fromCharCode(...new Uint8Array(exported)));

        // Do not add new lines so that its copyable from plain string representation.
        return `-----BEGIN PUBLIC KEY-----${exportedAsBase64}-----END PUBLIC KEY-----`
    }

    /**
     * Check and fill in the review payload so that its ready for signing.
     * See the [Mangrove Review Standard](https://mangrove.reviews/standard)
     * for more details.
     * Has to include at least `sub` and `rating` or `opinion`.
     * @param {Payload} payload Base {@link Payload} to be cleaned, it will be mutated.
     * @returns {Payload} Payload ready to sign - the same as param 'PayLoad'.
     */
    private static cleanPayload(payload: Review): Review {
        if (!payload.sub) throw 'Payload must include subject URI in `sub` field.'
        if (!payload.rating && !payload.opinion) throw 'Payload must include either rating or opinion.'
        if (payload.rating !== undefined) {
            if (payload.rating < 0 || payload.rating > 100) throw 'Rating must be in the range from 0 to 100.'
        }
        payload.iat = Math.floor(Date.now() / 1000)
        if (payload.rating === null) delete payload.rating
        if (!payload.opinion) delete payload.opinion
        if (!payload.images || !payload.images.length) delete payload.images
        const meta: Metadata = {client_id: window.location.href, ...payload.metadata}
        for (const key in meta) {
            const value = meta[key]
            if (value === null || value === false) {
                delete meta[key]
            }
        }
        payload.metadata = meta
        return payload
    }


}

