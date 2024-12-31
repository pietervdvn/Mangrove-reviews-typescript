import {MangroveReviews} from "../lib";

async function example() : Promise<void>{

    const subReviews = await MangroveReviews.getReviews({
        sub: "geo:51.4954589,11.9659188",
        q: "verwöner",
        u: 30,
        issuers: true,
        maresi_subjects: true
    });

    console.log(subReviews.reviews);
}

example()