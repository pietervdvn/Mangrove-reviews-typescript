import {JWTPayload} from "jose/dist/types/types";

export interface Metadata extends JWTPayload{

    /**
     * Identity of the client used to leave the review, gets populated if not provided.
     */
    client_id: string

    /**
     * Nickname of the reviewer.
     */
    nickname?: string
    given_name?: string
    family_name?: string
    
    age?: number
    
    gender?: string

    /**
     * The context in which the reviewer primarly had the experience with the subject
     */
    experience_context?: `business` | `family` | `couple` |`friends` | `solo`

    /**
     * Please set this flag to `true` when the reviewer had direct experience with the subject of the review
     */
    is_personal_experience?: boolean


    /**
     * Please set this flag to `true` when the review is left owner, employee of other affiliated person.
     */
    is_affiliated?: boolean


    /**
     * Please set this flag to `true` when review was automatically generated by a bot.
     */
    is_generated?: boolean

    
    /** Please provide the source of the review
     *  if the review does not originate from the author.
     */
    data_source?: string
}

export interface Review {
    /**
     * URI of the review subject.
     */
    sub: string
    /**
     *  Rating of subject between 0 and 100.
     */
    rating?: number

    /**
     * Opinion of subject with at most 500 characters.
     */
    opinion?: string
    
    /**
     * Unix timestamp of when review was issued,
     *  gets filled in automatically if not provided.
     */
    iat: number

    /**
     * Array of up to 5 images to be included.
     */
    images?: {
        /**
         * Public URL of an image.
         */
        src: string
        /**
         * Optional label of an image.
         */
        label?: string
    }[]
    
    /**
     *  Any {@link Metadata} relating to the issuer or circumstances of leaving review.
     *  See the [Mangrove Review Standard](https://mangrove.reviews/standard) for more.
     */
    metadata?: Metadata
}

 