export interface AtomMediaGroup {
    /** Contains a human readable title for the entry. This value should not be blank. */
    title: string;
    content?: AtomMediaLink;
    thumbnail?: AtomMediaLink;
    /** Conveys a short summary, abstract, or excerpt of the entry. Summary should be provided if there either is no content provided for the entry, or that content is not inline (i.e., contains a src attribute), or if the content is encoded in base64. */
    description?: string;
    community?: AtomMediaCommunity;
}

export interface AtomMediaCommunity {
    starRating: {
        count?: number;
        average?: number;
        min?: number;
        max?: number;
    };
    statistics: {
        view?: number;
    };
}

export interface AtomMediaLink {
    /** `url` is the URI of the referenced resource */
    url: string;
    type?: string;
    width?: number;
    height?: number;
}