// State privacy-policy review. Pure functions: no network access here.
// Each state lists what its privacy law generally expects a privacy policy or
// notice to describe. Finding or not finding text is evidence, not a legal
// conclusion, and whether a law applies to a business depends on thresholds
// this scan cannot see.
import * as cheerio from 'cheerio';

const text = (s) => (s || '').replace(/\s+/g, ' ').trim();

export const STATES = [
  { code: 'CA', name: 'California' }, { code: 'NY', name: 'New York' }, { code: 'FL', name: 'Florida' },
  { code: 'TX', name: 'Texas' }, { code: 'UT', name: 'Utah' }, { code: 'NV', name: 'Nevada' },
  { code: 'NJ', name: 'New Jersey' }, { code: 'AZ', name: 'Arizona' }, { code: 'CT', name: 'Connecticut' },
  { code: 'GA', name: 'Georgia' }, { code: 'VA', name: 'Virginia' },
];

// Cleans the free-text state name: letters, spaces, hyphens, apostrophes, periods; at most 12 words.
export function cleanOtherName(raw) {
  const words = String(raw || '').replace(/[^\p{L}\s.'-]/gu, ' ').split(/\s+/).filter(Boolean).slice(0, 12);
  return words.join(' ').slice(0, 100);
}

// Visible policy text only: no scripts, styles, menus, cookie banners or chat widgets.
export function policyText(html) {
  const strip = (root = 'body') => {
    const $p = cheerio.load(html);
    $p('script,style,noscript,template,svg,nav,header,footer,aside,[class*="cookie"],[id*="cookie"],[class*="consent"],[id*="consent"],[class*="chat"],[id*="chat"]').remove();
    return text($p(root).text());
  };
  const inMain = strip('main,[role="main"]');
  if (inMain.length >= 200) return inMain;
  const body = strip('body');
  if (body.length >= 200) return body;
  const $q = cheerio.load(html); $q('script,style,noscript,template,svg').remove();
  return text($q('body').text());
}

// Phrase tests (each describes wording a policy normally uses).
const P = {
  know: /right[^.]{0,80}\b(know|access)\b|\bknow what (personal )?(information|data)|\baccess,? (correct|or delete|and delete)|\bconfirm\b[^.]{0,50}(process|collect)/i,
  access: /\baccess\b/i,
  del: /delet(e|ion)|erase/i,
  correct: /\bcorrect(ion)?\b|rectif/i,
  port: /portab|copy of (your )?(personal )?(data|information)|receive (a )?copy/i,
  optout: /opt[- ]?out|do not sell|do not share/i,
  optoutSale: /opt[- ]?out[^.]{0,80}(sale|sell)|do not sell|not sell/i,
  targeted: /targeted advertis|cross[- ]context behavioral|interest-based|personalized advertis/i,
  profiling: /profil(e|ing)/i,
  sensitive: /sensitive (personal )?(data|information)/i,
  limitSens: /limit[^.]{0,80}sensitive/i,
  appeal: /appeal/i,
  nodisc: /discriminat|retaliat/i,
  gpc: /global privacy control|\bgpc\b|opt-out preference signal|universal opt-out/i,
  submit: /@[a-z0-9.-]+\.[a-z]{2,}|\b\d{3}[-.) ]+\d{3}[-. ]+\d{4}\b|toll[- ]free|submit a request|request form/i,
  categories: /categories of (personal )?(information|data)|information we collect|what information we collect|we collect/i,
  thirdCats: /(share|disclose|provide)[^.]{0,100}(third[- ]part|partners|service providers|advertis)|categories of (third|recipients)/i,
  retention: /retain|retention|how long we keep|keep (your|records)/i,
  agent: /authorized agent/i,
  verify: /verif(y|ication)/i,
  changes: /changes to this|we may update|updat(e|ed) (this|our) (privacy |cookie )?(& cookie )?policy|last updated/i,
  effective: /effective( date)?|last updated/i,
  nvReview: /request[^.]{0,60}(change|correct|updat)|review and (request|change)|update (your )?(personal )?information/i,
  txNotice: /may sell your sensitive personal data/i,
  security: /safeguard|secur(e|ity)/i,
};

const R = (id, label, re, level, note) => ({ id, label, re, level, note });

const COMMON_APPEAL = R('appeal', 'Explains how to appeal a refused request', P.appeal, 'warn', 'This law expects the policy or response process to describe an appeal route.');

const VA_LIKE = (extra = []) => [
  R('access', 'Right to access / confirm', P.access, 'warn'),
  R('correct', 'Right to correct', P.correct, 'warn'),
  R('delete', 'Right to delete', P.del, 'warn'),
  R('port', 'Data portability (copy of your data)', P.port, 'info'),
  R('optout', 'Opt-out of sale, targeted advertising or profiling', P.optout, 'warn'),
  R('targeted', 'Names targeted advertising', P.targeted, 'info'),
  R('sensitive', 'Mentions sensitive data / consent', P.sensitive, 'info', 'These laws generally require consent to process sensitive data. Only matters if the business handles it.'),
  COMMON_APPEAL,
  R('submit', 'Way to submit a request', P.submit, 'warn'),
  ...extra,
];

export const LAWS = {
  CA: {
    law: 'California Consumer Privacy Act as amended by the CPRA (CCPA)',
    applies: 'Generally for businesses with more than about $26.6M in annual revenue, or that buy, sell or share data of 100,000+ consumers or households, or earn 50%+ of revenue from selling or sharing data. Confirm with counsel.',
    rules: [
      R('know', 'Right to know / access', P.know, 'warn'),
      R('delete', 'Right to delete', P.del, 'warn'),
      R('correct', 'Right to correct', P.correct, 'warn'),
      R('optout', 'Right to opt out of sale or sharing', P.optout, 'warn'),
      R('limit', 'Right to limit use of sensitive information', P.limitSens, 'info', 'Only needed if sensitive personal information is used beyond what the law allows.'),
      R('nodisc', 'No discrimination for using rights', P.nodisc, 'warn'),
      R('gpc', 'Mentions Global Privacy Control / opt-out signal', P.gpc, 'warn'),
      R('categories', 'Describes categories of information collected', P.categories, 'warn'),
      R('thirdCats', 'Describes who information is shared with', P.thirdCats, 'warn'),
      R('retention', 'Describes how long information is kept', P.retention, 'info'),
      R('agent', 'Mentions authorized agents', P.agent, 'info'),
      R('submit', 'Way to submit a request', P.submit, 'warn'),
      R('date', 'Shows an update date', P.effective, 'warn', 'The CCPA expects the policy to be updated at least every 12 months.'),
    ],
  },
  VA: { law: 'Virginia Consumer Data Protection Act (VCDPA)', applies: 'Generally 100,000+ Virginia consumers a year, or 25,000+ plus over 50% of revenue from selling data.', rules: VA_LIKE() },
  CT: {
    law: 'Connecticut Data Privacy Act (CTDPA)',
    applies: 'Generally 35,000+ Connecticut consumers, with lower triggers for sensitive data or sales; amendments took effect July 1, 2026. Confirm with counsel.',
    rules: VA_LIKE([R('gpc', 'Mentions Global Privacy Control / opt-out signal', P.gpc, 'warn', 'Connecticut has required businesses to honor opt-out preference signals since January 1, 2025.')]),
  },
  NJ: {
    law: 'New Jersey Data Privacy Act (NJDPA)',
    applies: 'Generally 100,000+ New Jersey consumers, or 25,000+ with revenue or discounts from selling data. Confirm with counsel.',
    rules: VA_LIKE([R('gpc', 'Mentions Global Privacy Control / opt-out signal', P.gpc, 'warn', 'New Jersey requires recognition of universal opt-out signals.')]),
  },
  TX: {
    law: 'Texas Data Privacy and Security Act (TDPSA)',
    applies: 'Applies to businesses that are not SBA-defined small businesses; small businesses still face limits on selling sensitive data. Confirm with counsel.',
    rules: VA_LIKE([
      R('gpc', 'Mentions Global Privacy Control / opt-out signal', P.gpc, 'info', 'Texas recognizes universal opt-out signals.'),
      R('txNotice', 'Sensitive-data sale notice, if the business sells it', P.txNotice, 'info', 'A business that sells sensitive personal data must post: "NOTICE: We may sell your sensitive personal data." Only needed if it does.'),
    ]),
  },
  UT: {
    law: 'Utah Consumer Privacy Act (UCPA)',
    applies: 'Generally $25M+ in annual revenue and 100,000+ Utah consumers, or 25,000+ with over 50% of revenue from selling data. Confirm with counsel.',
    rules: [
      R('access', 'Right to access / confirm', P.access, 'warn'),
      R('delete', 'Right to delete', P.del, 'warn'),
      R('correct', 'Right to correct', P.correct, 'info', 'Utah added a correction right in 2026; confirm current wording with counsel.'),
      R('port', 'Data portability', P.port, 'info'),
      R('optout', 'Opt-out of sale or targeted advertising', P.optout, 'warn'),
      R('submit', 'Way to submit a request', P.submit, 'warn'),
    ],
  },
  FL: {
    law: 'Florida Digital Bill of Rights (FDBR)',
    applies: 'Full duties apply mainly to very large companies ($1B+ revenue plus a tech-platform trigger). The rule on selling sensitive data reaches any for-profit business doing business in Florida. Confirm with counsel.',
    rules: [
      R('access', 'Right to access / confirm', P.access, 'warn'),
      R('correct', 'Right to correct', P.correct, 'warn'),
      R('delete', 'Right to delete', P.del, 'warn'),
      R('optout', 'Opt-out of sale or targeted advertising', P.optout, 'warn'),
      R('appeal', 'Explains how to appeal a refused request', P.appeal, 'info'),
      R('sensitive', 'Mentions sensitive data', P.sensitive, 'info', 'Florida requires a notice if a business sells sensitive data: "NOTICE: This website may sell your sensitive personal data." Only needed if it does.'),
      R('submit', 'Way to submit a request', P.submit, 'warn'),
    ],
  },
  NV: {
    law: 'Nevada online privacy law (NRS 603A.300 to 603A.360)',
    applies: 'Applies to operators of commercial websites or online services that collect personal information from Nevada consumers. Confirm with counsel.',
    rules: [
      R('categories', 'Describes categories of information collected', P.categories, 'warn'),
      R('thirdCats', 'Describes categories of third parties it is shared with', P.thirdCats, 'warn'),
      R('review', 'Explains how consumers can review or request changes', P.nvReview, 'warn'),
      R('changes', 'Explains how consumers are told about changes', P.changes, 'warn'),
      R('date', 'Shows an effective date', P.effective, 'warn'),
      R('optoutSale', 'Opt-out of the sale of information, with a request method', P.optoutSale, 'warn', 'Nevada lets consumers submit a verified opt-out request; a designated email, toll-free number or web form is expected.'),
      R('submit', 'Contact method for requests', P.submit, 'warn'),
    ],
  },
};

// States with no general consumer privacy statute in the reference this lab uses (October 2026).
const NO_LAW = {
  NY: 'New York has no comprehensive consumer privacy law in the reference this lab uses. Its SHIELD Act is about data security and breach notification.',
  AZ: 'Arizona has no comprehensive consumer privacy law in the reference this lab uses.',
  GA: 'Georgia has no comprehensive consumer privacy law in the reference this lab uses.',
};
const BASELINE = [
  R('categories', 'Describes what information is collected', P.categories, 'info'),
  R('thirdCats', 'Describes who information is shared with', P.thirdCats, 'info'),
  R('rights', 'Describes choices or rights (access, delete, opt out)', /\b(access|delete|opt[- ]?out)\b/i, 'info'),
  R('submit', 'Contact method for privacy questions', P.submit, 'info'),
  R('date', 'Shows an update or effective date', P.effective, 'info'),
];

export function reviewState({ state, other, policyHtml, policyUrl }) {
  const code = String(state || '').toUpperCase();
  const known = STATES.find((s) => s.code === code);
  const otherName = code === 'OTHER' ? cleanOtherName(other) : '';
  if (!known && !(code === 'OTHER' && otherName)) return null;
  const name = known ? known.name : otherName;

  const group = {
    id: 'state',
    title: `State privacy policy review: ${name}`,
    intro: '',
    checks: [],
  };
  const add = (id, label, status, detail) => group.checks.push({ id: 'st-' + id, label, status, detail });

  let law = known && LAWS[code];
  let rules = law ? law.rules : BASELINE;
  if (law) {
    group.intro = `${law.law}. ${law.applies} These checks look for the items this law generally expects a privacy policy to describe. They are evidence from the page, not a legal conclusion.`;
  } else if (known && NO_LAW[code]) {
    group.intro = `${NO_LAW[code]} The checks below are a general baseline only. Laws change, so confirm with counsel.${code === 'NY' ? ' New York policies are also commonly expected to describe how information is kept secure.' : ''}`;
    if (code === 'NY') rules = BASELINE.concat([R('security', 'Mentions safeguards for information', P.security, 'info')]);
  } else {
    group.intro = `This lab has no built-in rules for "${name}", so it applies a general baseline only. Check that state's current law with counsel.`;
  }

  if (!policyHtml) {
    add('policy', 'Privacy policy page was readable', 'na', 'The privacy policy could not be found or read, so none of the state items were checked.');
    return group;
  }
  const pl = policyText(policyHtml);
  add('policy', 'Privacy policy text reviewed', 'pass', `Read ${policyUrl || 'the privacy policy page'} (${pl.length.toLocaleString()} characters of visible text).`);
  for (const r of rules) {
    const found = r.re.test(pl);
    if (found) add(r.id, r.label, 'pass', 'Wording about this was found in the policy.');
    else add(r.id, r.label, r.level, `Not found in the policy text.${r.note ? ' ' + r.note : ''}`);
  }
  return group;
}
