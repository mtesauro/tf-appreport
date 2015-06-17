// structs.go
// data structuctures for the ThreadFix REST API library
package main

var defReport = `<?xml version="1.0" encoding="UTF-8"?>

<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" xmlns:dr3d="urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0" xmlns:math="http://www.w3.org/1998/Math/MathML" xmlns:form="urn:oasis:names:tc:opendocument:xmlns:form:1.0" xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0" xmlns:ooo="http://openoffice.org/2004/office" xmlns:ooow="http://openoffice.org/2004/writer" xmlns:oooc="http://openoffice.org/2004/calc" xmlns:dom="http://www.w3.org/2001/xml-events" xmlns:xforms="http://www.w3.org/2002/xforms" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:rpt="http://openoffice.org/2005/report" xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2" xmlns:xhtml="http://www.w3.org/1999/xhtml" xmlns:grddl="http://www.w3.org/2003/g/data-view#" xmlns:officeooo="http://openoffice.org/2009/office" xmlns:tableooo="http://openoffice.org/2009/table" xmlns:drawooo="http://openoffice.org/2010/draw" xmlns:calcext="urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0" xmlns:loext="urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0" xmlns:field="urn:openoffice:names:experimental:ooo-ms-interop:xmlns:field:1.0" xmlns:formx="urn:openoffice:names:experimental:ooxml-odf-interop:xmlns:form:1.0" xmlns:css3t="http://www.w3.org/TR/css3-text/" office:version="1.2" office:mimetype="application/vnd.oasis.opendocument.text">
 <office:meta><meta:initial-creator>Matt Tesauro</meta:initial-creator><meta:creation-date>2015-05-10T15:01:21.786739006</meta:creation-date><dc:date>2015-05-14T12:07:04.959467197</dc:date><dc:creator>Matt Tesauro</dc:creator><meta:editing-duration>PT22H44M35S</meta:editing-duration><meta:editing-cycles>7</meta:editing-cycles><meta:generator>LibreOffice/4.4.2.2$Linux_X86_64 LibreOffice_project/40m0$Build-2</meta:generator><meta:document-statistic meta:table-count="1" meta:image-count="0" meta:object-count="0" meta:page-count="5" meta:paragraph-count="52" meta:word-count="449" meta:character-count="2762" meta:non-whitespace-character-count="2364"/></office:meta>
 <office:settings>
  <config:config-item-set config:name="ooo:view-settings">
   <config:config-item config:name="ViewAreaTop" config:type="long">26</config:config-item>
   <config:config-item config:name="ViewAreaLeft" config:type="long">0</config:config-item>
   <config:config-item config:name="ViewAreaWidth" config:type="long">31487</config:config-item>
   <config:config-item config:name="ViewAreaHeight" config:type="long">14845</config:config-item>
   <config:config-item config:name="ShowRedlineChanges" config:type="boolean">true</config:config-item>
   <config:config-item config:name="InBrowseMode" config:type="boolean">false</config:config-item>
   <config:config-item-map-indexed config:name="Views">
    <config:config-item-map-entry>
     <config:config-item config:name="ViewId" config:type="string">view2</config:config-item>
     <config:config-item config:name="ViewLeft" config:type="long">15520</config:config-item>
     <config:config-item config:name="ViewTop" config:type="long">16133</config:config-item>
     <config:config-item config:name="VisibleLeft" config:type="long">0</config:config-item>
     <config:config-item config:name="VisibleTop" config:type="long">26</config:config-item>
     <config:config-item config:name="VisibleRight" config:type="long">31485</config:config-item>
     <config:config-item config:name="VisibleBottom" config:type="long">14870</config:config-item>
     <config:config-item config:name="ZoomType" config:type="short">0</config:config-item>
     <config:config-item config:name="ViewLayoutColumns" config:type="short">0</config:config-item>
     <config:config-item config:name="ViewLayoutBookMode" config:type="boolean">false</config:config-item>
     <config:config-item config:name="ZoomFactor" config:type="short">100</config:config-item>
     <config:config-item config:name="IsSelectedFrame" config:type="boolean">false</config:config-item>
    </config:config-item-map-entry>
   </config:config-item-map-indexed>
  </config:config-item-set>
  <config:config-item-set config:name="ooo:configuration-settings">
   <config:config-item config:name="PrintFaxName" config:type="string"/>
   <config:config-item config:name="PrintAnnotationMode" config:type="short">0</config:config-item>
   <config:config-item config:name="PrintControls" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrintPageBackground" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrintRightPages" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrintProspect" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintSingleJobs" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintEmptyPages" config:type="boolean">false</config:config-item>
   <config:config-item config:name="ApplyParagraphMarkFormatToNumbering" config:type="boolean">false</config:config-item>
   <config:config-item config:name="TabOverMargin" config:type="boolean">false</config:config-item>
   <config:config-item config:name="EmbedSystemFonts" config:type="boolean">false</config:config-item>
   <config:config-item config:name="EmbedFonts" config:type="boolean">false</config:config-item>
   <config:config-item config:name="BackgroundParaOverDrawings" config:type="boolean">false</config:config-item>
   <config:config-item config:name="UnbreakableNumberings" config:type="boolean">false</config:config-item>
   <config:config-item config:name="TabOverflow" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PropLineSpacingShrinksFirstLine" config:type="boolean">false</config:config-item>
   <config:config-item config:name="SmallCapsPercentage66" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintDrawings" config:type="boolean">true</config:config-item>
   <config:config-item config:name="CollapseEmptyCellPara" config:type="boolean">true</config:config-item>
   <config:config-item config:name="RsidRoot" config:type="int">344368</config:config-item>
   <config:config-item config:name="UnxForceZeroExtLeading" config:type="boolean">false</config:config-item>
   <config:config-item config:name="ClipAsCharacterAnchoredWriterFlyFrames" config:type="boolean">false</config:config-item>
   <config:config-item config:name="ClippedPictures" config:type="boolean">false</config:config-item>
   <config:config-item config:name="DoNotCaptureDrawObjsOnPage" config:type="boolean">false</config:config-item>
   <config:config-item config:name="LoadReadonly" config:type="boolean">false</config:config-item>
   <config:config-item config:name="IgnoreTabsAndBlanksForLineCalculation" config:type="boolean">false</config:config-item>
   <config:config-item config:name="DoNotResetParaAttrsForNumFont" config:type="boolean">false</config:config-item>
   <config:config-item config:name="DoNotJustifyLinesWithManualBreak" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintBlackFonts" config:type="boolean">false</config:config-item>
   <config:config-item config:name="UseFormerTextWrapping" config:type="boolean">false</config:config-item>
   <config:config-item config:name="TabsRelativeToIndent" config:type="boolean">true</config:config-item>
   <config:config-item config:name="AddParaSpacingToTableCells" config:type="boolean">true</config:config-item>
   <config:config-item config:name="TableRowKeep" config:type="boolean">false</config:config-item>
   <config:config-item config:name="UseOldPrinterMetrics" config:type="boolean">false</config:config-item>
   <config:config-item config:name="UseFormerLineSpacing" config:type="boolean">false</config:config-item>
   <config:config-item config:name="TabAtLeftIndentForParagraphsInList" config:type="boolean">false</config:config-item>
   <config:config-item config:name="AllowPrintJobCancel" config:type="boolean">true</config:config-item>
   <config:config-item config:name="UseOldNumbering" config:type="boolean">false</config:config-item>
   <config:config-item config:name="AddExternalLeading" config:type="boolean">true</config:config-item>
   <config:config-item config:name="FloattableNomargins" config:type="boolean">false</config:config-item>
   <config:config-item config:name="SurroundTextWrapSmall" config:type="boolean">false</config:config-item>
   <config:config-item config:name="IsLabelDocument" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintReversed" config:type="boolean">false</config:config-item>
   <config:config-item config:name="IgnoreFirstLineIndentInNumbering" config:type="boolean">false</config:config-item>
   <config:config-item config:name="UseFormerObjectPositioning" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintTables" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrinterIndependentLayout" config:type="string">high-resolution</config:config-item>
   <config:config-item config:name="SaveVersionOnClose" config:type="boolean">false</config:config-item>
   <config:config-item config:name="CurrentDatabaseCommand" config:type="string"/>
   <config:config-item config:name="CurrentDatabaseDataSource" config:type="string"/>
   <config:config-item config:name="OutlineLevelYieldsNumbering" config:type="boolean">false</config:config-item>
   <config:config-item config:name="ConsiderTextWrapOnObjPos" config:type="boolean">false</config:config-item>
   <config:config-item config:name="CurrentDatabaseCommandType" config:type="int">0</config:config-item>
   <config:config-item config:name="RedlineProtectionKey" config:type="base64Binary"/>
   <config:config-item config:name="Rsid" config:type="int">747355</config:config-item>
   <config:config-item config:name="PrintProspectRTL" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrinterSetup" config:type="base64Binary"/>
   <config:config-item config:name="AlignTabStopPosition" config:type="boolean">true</config:config-item>
   <config:config-item config:name="ProtectForm" config:type="boolean">false</config:config-item>
   <config:config-item config:name="InvertBorderSpacing" config:type="boolean">false</config:config-item>
   <config:config-item config:name="AddParaTableSpacingAtStart" config:type="boolean">true</config:config-item>
   <config:config-item config:name="CharacterCompressionType" config:type="short">0</config:config-item>
   <config:config-item config:name="ApplyUserData" config:type="boolean">true</config:config-item>
   <config:config-item config:name="AddParaTableSpacing" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrintPaperFromSetup" config:type="boolean">false</config:config-item>
   <config:config-item config:name="ChartAutoUpdate" config:type="boolean">true</config:config-item>
   <config:config-item config:name="FieldAutoUpdate" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrintHiddenText" config:type="boolean">false</config:config-item>
   <config:config-item config:name="IsKernAsianPunctuation" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintTextPlaceholder" config:type="boolean">false</config:config-item>
   <config:config-item config:name="PrintGraphics" config:type="boolean">true</config:config-item>
   <config:config-item config:name="StylesNoDefault" config:type="boolean">false</config:config-item>
   <config:config-item config:name="AddFrameOffsets" config:type="boolean">false</config:config-item>
   <config:config-item config:name="UpdateFromTemplate" config:type="boolean">true</config:config-item>
   <config:config-item config:name="MathBaselineAlignment" config:type="boolean">true</config:config-item>
   <config:config-item config:name="PrinterName" config:type="string"/>
   <config:config-item config:name="LinkUpdateMode" config:type="short">1</config:config-item>
   <config:config-item config:name="PrintLeftPages" config:type="boolean">true</config:config-item>
   <config:config-item config:name="SaveGlobalDocumentLinks" config:type="boolean">false</config:config-item>
  </config:config-item-set>
 </office:settings>
 <office:scripts>
  <office:script script:language="ooo:Basic">
   <ooo:libraries xmlns:ooo="http://openoffice.org/2004/office" xmlns:xlink="http://www.w3.org/1999/xlink">
    <ooo:library-embedded ooo:name="Standard"/>
   </ooo:libraries>
  </office:script>
 </office:scripts>
 <office:font-face-decls>
  <style:font-face style:name="OpenSymbol" svg:font-family="OpenSymbol" style:font-charset="x-symbol"/>
  <style:font-face style:name="Arial" svg:font-family="Arial, sans-serif"/>
  <style:font-face style:name="FreeSans1" svg:font-family="FreeSans" style:font-family-generic="swiss"/>
  <style:font-face style:name="Liberation Serif" svg:font-family="&apos;Liberation Serif&apos;" style:font-family-generic="roman" style:font-pitch="variable"/>
  <style:font-face style:name="Liberation Sans" svg:font-family="&apos;Liberation Sans&apos;" style:font-family-generic="swiss" style:font-pitch="variable"/>
  <style:font-face style:name="Droid Sans Fallback" svg:font-family="&apos;Droid Sans Fallback&apos;" style:font-family-generic="system" style:font-pitch="variable"/>
  <style:font-face style:name="FreeSans" svg:font-family="FreeSans" style:font-family-generic="system" style:font-pitch="variable"/>
 </office:font-face-decls>
 <office:styles>
  <style:default-style style:family="graphic">
   <style:graphic-properties svg:stroke-color="#3465a4" draw:fill-color="#729fcf" fo:wrap-option="no-wrap" draw:shadow-offset-x="0.1181in" draw:shadow-offset-y="0.1181in" draw:start-line-spacing-horizontal="0.1114in" draw:start-line-spacing-vertical="0.1114in" draw:end-line-spacing-horizontal="0.1114in" draw:end-line-spacing-vertical="0.1114in" style:flow-with-text="false"/>
   <style:paragraph-properties style:text-autospace="ideograph-alpha" style:line-break="strict" style:writing-mode="lr-tb" style:font-independent-line-spacing="false">
    <style:tab-stops/>
   </style:paragraph-properties>
   <style:text-properties style:use-window-font-color="true" style:font-name="Liberation Serif" fo:font-size="12pt" fo:language="en" fo:country="US" style:letter-kerning="true" style:font-name-asian="Droid Sans Fallback" style:font-size-asian="10.5pt" style:language-asian="zh" style:country-asian="CN" style:font-name-complex="FreeSans" style:font-size-complex="12pt" style:language-complex="hi" style:country-complex="IN"/>
  </style:default-style>
  <style:default-style style:family="paragraph">
   <style:paragraph-properties fo:hyphenation-ladder-count="no-limit" style:text-autospace="ideograph-alpha" style:punctuation-wrap="hanging" style:line-break="strict" style:tab-stop-distance="0.4925in" style:writing-mode="page"/>
   <style:text-properties style:use-window-font-color="true" style:font-name="Liberation Serif" fo:font-size="12pt" fo:language="en" fo:country="US" style:letter-kerning="true" style:font-name-asian="Droid Sans Fallback" style:font-size-asian="10.5pt" style:language-asian="zh" style:country-asian="CN" style:font-name-complex="FreeSans" style:font-size-complex="12pt" style:language-complex="hi" style:country-complex="IN" fo:hyphenate="false" fo:hyphenation-remain-char-count="2" fo:hyphenation-push-char-count="2"/>
  </style:default-style>
  <style:default-style style:family="table">
   <style:table-properties table:border-model="collapsing"/>
  </style:default-style>
  <style:default-style style:family="table-row">
   <style:table-row-properties fo:keep-together="auto"/>
  </style:default-style>
  <style:style style:name="Standard" style:family="paragraph" style:class="text"/>
  <style:style style:name="Heading" style:family="paragraph" style:parent-style-name="Standard" style:next-style-name="Text_20_body" style:class="text">
   <style:paragraph-properties fo:margin-top="0.1665in" fo:margin-bottom="0.0835in" loext:contextual-spacing="false" fo:keep-with-next="always"/>
   <style:text-properties style:font-name="Liberation Sans" fo:font-family="&apos;Liberation Sans&apos;" style:font-family-generic="swiss" style:font-pitch="variable" fo:font-size="14pt" style:font-name-asian="Droid Sans Fallback" style:font-family-asian="&apos;Droid Sans Fallback&apos;" style:font-family-generic-asian="system" style:font-pitch-asian="variable" style:font-size-asian="14pt" style:font-name-complex="FreeSans" style:font-family-complex="FreeSans" style:font-family-generic-complex="system" style:font-pitch-complex="variable" style:font-size-complex="14pt"/>
  </style:style>
  <style:style style:name="Text_20_body" style:display-name="Text body" style:family="paragraph" style:parent-style-name="Standard" style:class="text">
   <style:paragraph-properties fo:margin-top="0in" fo:margin-bottom="0.0972in" loext:contextual-spacing="false" fo:line-height="120%"/>
  </style:style>
  <style:style style:name="List" style:family="paragraph" style:parent-style-name="Text_20_body" style:class="list">
   <style:text-properties style:font-size-asian="12pt" style:font-name-complex="FreeSans1" style:font-family-complex="FreeSans" style:font-family-generic-complex="swiss"/>
  </style:style>
  <style:style style:name="Caption" style:family="paragraph" style:parent-style-name="Standard" style:class="extra">
   <style:paragraph-properties fo:margin-top="0.0835in" fo:margin-bottom="0.0835in" loext:contextual-spacing="false" text:number-lines="false" text:line-number="0"/>
   <style:text-properties fo:font-size="12pt" fo:font-style="italic" style:font-size-asian="12pt" style:font-style-asian="italic" style:font-name-complex="FreeSans1" style:font-family-complex="FreeSans" style:font-family-generic-complex="swiss" style:font-size-complex="12pt" style:font-style-complex="italic"/>
  </style:style>
  <style:style style:name="Index" style:family="paragraph" style:parent-style-name="Standard" style:class="index">
   <style:paragraph-properties text:number-lines="false" text:line-number="0"/>
   <style:text-properties style:font-size-asian="12pt" style:font-name-complex="FreeSans1" style:font-family-complex="FreeSans" style:font-family-generic-complex="swiss"/>
  </style:style>
  <style:style style:name="Footer" style:family="paragraph" style:parent-style-name="Standard" style:class="extra">
   <style:paragraph-properties text:number-lines="false" text:line-number="0">
    <style:tab-stops>
     <style:tab-stop style:position="3.4626in" style:type="center"/>
     <style:tab-stop style:position="6.9252in" style:type="right"/>
    </style:tab-stops>
   </style:paragraph-properties>
  </style:style>
  <style:style style:name="Table_20_Contents" style:display-name="Table Contents" style:family="paragraph" style:parent-style-name="Standard" style:class="extra">
   <style:paragraph-properties text:number-lines="false" text:line-number="0"/>
  </style:style>
  <style:style style:name="Quotations" style:family="paragraph" style:parent-style-name="Standard" style:class="html">
   <style:paragraph-properties fo:margin-left="0.3937in" fo:margin-right="0.3937in" fo:margin-top="0in" fo:margin-bottom="0.1965in" loext:contextual-spacing="false" fo:text-indent="0in" style:auto-text-indent="false"/>
  </style:style>
  <style:style style:name="Title" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:class="chapter">
   <style:paragraph-properties fo:text-align="center" style:justify-single-word="false"/>
   <style:text-properties fo:font-size="28pt" fo:font-weight="bold" style:font-size-asian="28pt" style:font-weight-asian="bold" style:font-size-complex="28pt" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="Subtitle" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:class="chapter">
   <style:paragraph-properties fo:margin-top="0.0417in" fo:margin-bottom="0.0835in" loext:contextual-spacing="false" fo:text-align="center" style:justify-single-word="false"/>
   <style:text-properties fo:font-size="18pt" style:font-size-asian="18pt" style:font-size-complex="18pt"/>
  </style:style>
  <style:style style:name="Heading_20_1" style:display-name="Heading 1" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:default-outline-level="1" style:class="text">
   <style:paragraph-properties fo:margin-top="0.1665in" fo:margin-bottom="0.0835in" loext:contextual-spacing="false"/>
   <style:text-properties fo:font-size="130%" fo:font-weight="bold" style:font-size-asian="130%" style:font-weight-asian="bold" style:font-size-complex="130%" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="Heading_20_2" style:display-name="Heading 2" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:default-outline-level="2" style:class="text">
   <style:paragraph-properties fo:margin-top="0.139in" fo:margin-bottom="0.0835in" loext:contextual-spacing="false"/>
   <style:text-properties fo:font-size="115%" fo:font-weight="bold" style:font-size-asian="115%" style:font-weight-asian="bold" style:font-size-complex="115%" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="Heading_20_3" style:display-name="Heading 3" style:family="paragraph" style:parent-style-name="Heading" style:next-style-name="Text_20_body" style:default-outline-level="3" style:class="text">
   <style:paragraph-properties fo:margin-top="0.0972in" fo:margin-bottom="0.0835in" loext:contextual-spacing="false"/>
   <style:text-properties fo:color="#808080" fo:font-size="14pt" fo:font-weight="bold" style:font-size-asian="14pt" style:font-weight-asian="bold" style:font-size-complex="14pt" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="Contents_20_Heading" style:display-name="Contents Heading" style:family="paragraph" style:parent-style-name="Heading" style:class="index">
   <style:paragraph-properties fo:margin-left="0in" fo:margin-right="0in" fo:text-indent="0in" style:auto-text-indent="false" text:number-lines="false" text:line-number="0"/>
   <style:text-properties fo:font-size="16pt" fo:font-weight="bold" style:font-size-asian="16pt" style:font-weight-asian="bold" style:font-size-complex="16pt" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="Contents_20_2" style:display-name="Contents 2" style:family="paragraph" style:parent-style-name="Index" style:class="index">
   <style:paragraph-properties fo:margin-left="0.1965in" fo:margin-right="0in" fo:text-indent="0in" style:auto-text-indent="false">
    <style:tab-stops>
     <style:tab-stop style:position="6.7283in" style:type="right" style:leader-style="dotted" style:leader-text="."/>
    </style:tab-stops>
   </style:paragraph-properties>
  </style:style>
  <style:style style:name="Contents_20_3" style:display-name="Contents 3" style:family="paragraph" style:parent-style-name="Index" style:class="index">
   <style:paragraph-properties fo:margin-left="0.3929in" fo:margin-right="0in" fo:text-indent="0in" style:auto-text-indent="false">
    <style:tab-stops>
     <style:tab-stop style:position="6.5319in" style:type="right" style:leader-style="dotted" style:leader-text="."/>
    </style:tab-stops>
   </style:paragraph-properties>
  </style:style>
  <style:style style:name="Text_20_Body.Standard" style:display-name="Text Body.Standard" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:paragraph-properties fo:text-align="start" style:justify-single-word="false" fo:padding="0in" fo:border="none"/>
   <style:text-properties fo:font-variant="normal" fo:text-transform="none" fo:color="#000000" style:text-line-through-style="none" style:text-line-through-type="none" style:font-name="Arial" fo:font-family="Arial, sans-serif" fo:font-size="10.5pt" style:text-underline-style="none" style:text-blinking="false" style:font-name-asian="Arial" style:font-family-asian="Arial, sans-serif" style:font-size-asian="10.5pt" style:font-name-complex="Arial" style:font-family-complex="Arial, sans-serif" style:font-size-complex="10.5pt" style:text-overline-style="none" style:text-overline-color="font-color"/>
  </style:style>
  <style:style style:name="Bullet_20_Symbols" style:display-name="Bullet Symbols" style:family="text">
   <style:text-properties style:font-name="OpenSymbol" fo:font-family="OpenSymbol" style:font-charset="x-symbol" style:font-name-asian="OpenSymbol" style:font-family-asian="OpenSymbol" style:font-charset-asian="x-symbol" style:font-name-complex="OpenSymbol" style:font-family-complex="OpenSymbol" style:font-charset-complex="x-symbol"/>
  </style:style>
  <style:style style:name="Internet_20_link" style:display-name="Internet link" style:family="text">
   <style:text-properties fo:color="#000080" fo:language="zxx" fo:country="none" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color" style:language-asian="zxx" style:country-asian="none" style:language-complex="zxx" style:country-complex="none"/>
  </style:style>
  <style:style style:name="Index_20_Link" style:display-name="Index Link" style:family="text"/>
  <style:style style:name="Graphics" style:family="graphic">
   <style:graphic-properties text:anchor-type="paragraph" svg:x="0in" svg:y="0in" style:wrap="dynamic" style:number-wrapped-paragraphs="no-limit" style:wrap-contour="false" style:vertical-pos="top" style:vertical-rel="paragraph" style:horizontal-pos="center" style:horizontal-rel="paragraph"/>
  </style:style>
  <text:outline-style style:name="Outline">
   <text:outline-level-style text:level="1" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.3in" fo:text-indent="-0.3in" fo:margin-left="0.3in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="2" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.4in" fo:text-indent="-0.4in" fo:margin-left="0.4in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="3" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.5in" fo:text-indent="-0.5in" fo:margin-left="0.5in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="4" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.6in" fo:text-indent="-0.6in" fo:margin-left="0.6in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="5" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.7in" fo:text-indent="-0.7in" fo:margin-left="0.7in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="6" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.8in" fo:text-indent="-0.8in" fo:margin-left="0.8in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="7" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.9in" fo:text-indent="-0.9in" fo:margin-left="0.9in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="8" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1in" fo:text-indent="-1in" fo:margin-left="1in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="9" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.1in" fo:text-indent="-1.1in" fo:margin-left="1.1in"/>
    </style:list-level-properties>
   </text:outline-level-style>
   <text:outline-level-style text:level="10" style:num-format="">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.2in" fo:text-indent="-1.2in" fo:margin-left="1.2in"/>
    </style:list-level-properties>
   </text:outline-level-style>
  </text:outline-style>
  <text:notes-configuration text:note-class="footnote" style:num-format="1" text:start-value="0" text:footnotes-position="page" text:start-numbering-at="document"/>
  <text:notes-configuration text:note-class="endnote" style:num-format="i" text:start-value="0"/>
  <text:linenumbering-configuration text:number-lines="false" text:offset="0.1965in" style:num-format="1" text:number-position="left" text:increment="5"/>
 </office:styles>
 <office:automatic-styles>
  <style:style style:name="Table1" style:family="table">
   <style:table-properties style:width="6.925in" table:align="margins"/>
  </style:style>
  <style:style style:name="Table1.A" style:family="table-column">
   <style:table-column-properties style:column-width="2.7701in" style:rel-column-width="26214*"/>
  </style:style>
  <style:style style:name="Table1.B" style:family="table-column">
   <style:table-column-properties style:column-width="1.3847in" style:rel-column-width="13107*"/>
  </style:style>
  <style:style style:name="Table1.A1" style:family="table-cell">
   <style:table-cell-properties fo:padding="0.0382in" fo:border="none"/>
  </style:style>
  <style:style style:name="Table1" style:family="table">
   <style:table-properties style:width="6.925in" table:align="margins"/>
  </style:style>
  <style:style style:name="Table1.A" style:family="table-column">
   <style:table-column-properties style:column-width="2.7701in" style:rel-column-width="26214*"/>
  </style:style>
  <style:style style:name="Table1.B" style:family="table-column">
   <style:table-column-properties style:column-width="1.3847in" style:rel-column-width="13107*"/>
  </style:style>
  <style:style style:name="Table1.A1" style:family="table-cell">
   <style:table-cell-properties fo:padding="0.0382in" fo:border="none"/>
  </style:style>
  <style:style style:name="P1" style:family="paragraph" style:parent-style-name="Footer">
   <style:paragraph-properties fo:text-align="end" style:justify-single-word="false"/>
   <style:text-properties officeooo:paragraph-rsid="00054130"/>
  </style:style>
  <style:style style:name="P2" style:family="paragraph" style:parent-style-name="Footer">
   <style:paragraph-properties fo:text-align="end" style:justify-single-word="false"/>
   <style:text-properties officeooo:paragraph-rsid="00054130"/>
  </style:style>
  <style:style style:name="P3" style:family="paragraph" style:parent-style-name="Standard">
   <style:text-properties officeooo:rsid="00054130" officeooo:paragraph-rsid="00054130"/>
  </style:style>
  <style:style style:name="P4" style:family="paragraph" style:parent-style-name="Standard">
   <style:text-properties fo:font-size="24pt" style:font-size-asian="24pt" style:font-size-complex="24pt"/>
  </style:style>
  <style:style style:name="P5" style:family="paragraph" style:parent-style-name="Standard">
   <style:text-properties fo:font-size="24pt" officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec" style:font-size-asian="24pt" style:font-size-complex="24pt"/>
  </style:style>
  <style:style style:name="P6" style:family="paragraph" style:parent-style-name="Standard">
   <style:paragraph-properties fo:text-align="center" style:justify-single-word="false"/>
   <style:text-properties fo:font-size="24pt" officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec" style:font-size-asian="24pt" style:font-size-complex="24pt"/>
  </style:style>
  <style:style style:name="P7" style:family="paragraph" style:parent-style-name="Standard">
   <style:paragraph-properties fo:text-align="center" style:justify-single-word="false"/>
   <style:text-properties fo:font-size="24pt" officeooo:rsid="000590ec" officeooo:paragraph-rsid="00098d4f" style:font-size-asian="24pt" style:font-size-complex="24pt"/>
  </style:style>
  <style:style style:name="P8" style:family="paragraph" style:parent-style-name="Standard">
   <style:paragraph-properties fo:text-align="center" style:justify-single-word="false"/>
   <style:text-properties fo:font-size="32pt" fo:font-weight="bold" officeooo:rsid="00054130" officeooo:paragraph-rsid="000590ec" style:font-size-asian="32pt" style:font-weight-asian="bold" style:font-size-complex="32pt" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P9" style:family="paragraph" style:parent-style-name="Heading_20_2">
   <style:paragraph-properties fo:break-before="page"/>
  </style:style>
  <style:style style:name="P10" style:family="paragraph" style:parent-style-name="Heading_20_2">
   <style:paragraph-properties fo:break-before="page"/>
   <style:text-properties officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec"/>
  </style:style>
  <style:style style:name="P11" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec"/>
  </style:style>
  <style:style style:name="P12" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:paragraph-rsid="000590ec"/>
  </style:style>
  <style:style style:name="P13" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88"/>
  </style:style>
  <style:style style:name="P14" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties fo:font-weight="bold" officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88" style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P15" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties fo:font-weight="bold" officeooo:rsid="0007c9b3" officeooo:paragraph-rsid="0007c9b3" style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P16" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties fo:font-style="italic" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color" fo:font-weight="bold" officeooo:paragraph-rsid="0005ce88" style:font-style-asian="italic" style:font-weight-asian="bold" style:font-style-complex="italic" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P17" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties fo:font-style="italic" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color" fo:font-weight="bold" officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88" style:font-style-asian="italic" style:font-weight-asian="bold" style:font-style-complex="italic" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P18" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="0007c9b3" officeooo:paragraph-rsid="0007c9b3"/>
  </style:style>
  <style:style style:name="P19" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="0008c17b" officeooo:paragraph-rsid="0008c17b"/>
  </style:style>
  <style:style style:name="P20" style:family="paragraph" style:parent-style-name="Contents_20_2">
   <style:paragraph-properties>
    <style:tab-stops>
     <style:tab-stop style:position="6.7283in" style:type="right" style:leader-style="dotted" style:leader-text="."/>
    </style:tab-stops>
   </style:paragraph-properties>
  </style:style>
  <style:style style:name="P21" style:family="paragraph" style:parent-style-name="Table_20_Contents">
   <style:paragraph-properties fo:text-align="end" style:justify-single-word="false"/>
  </style:style>
  <style:style style:name="P22" style:family="paragraph" style:parent-style-name="Table_20_Contents">
   <style:paragraph-properties fo:text-align="start" style:justify-single-word="false"/>
   <style:text-properties officeooo:rsid="00054130" officeooo:paragraph-rsid="00054130"/>
  </style:style>
  <style:style style:name="P23" style:family="paragraph" style:parent-style-name="Table_20_Contents">
   <style:paragraph-properties fo:text-align="center" style:justify-single-word="false"/>
   <style:text-properties fo:font-style="italic" fo:font-weight="bold" officeooo:rsid="00054130" officeooo:paragraph-rsid="00054130" style:font-style-asian="italic" style:font-weight-asian="bold" style:font-style-complex="italic" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P24" style:family="paragraph" style:parent-style-name="Table_20_Contents">
   <style:text-properties officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec"/>
  </style:style>
  <style:style style:name="P25" style:family="paragraph" style:parent-style-name="Table_20_Contents">
   <style:paragraph-properties fo:text-align="end" style:justify-single-word="false"/>
   <style:text-properties officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec"/>
  </style:style>
  <style:style style:name="P26" style:family="paragraph" style:parent-style-name="Text_20_body" style:list-style-name="L1">
   <style:text-properties officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88"/>
  </style:style>
  <style:style style:name="P27" style:family="paragraph" style:parent-style-name="Text_20_body" style:list-style-name="L3">
   <style:text-properties officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88"/>
  </style:style>
  <style:style style:name="P28" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88"/>
  </style:style>
  <style:style style:name="P29" style:family="paragraph" style:parent-style-name="Text_20_body" style:list-style-name="L3">
   <style:text-properties fo:font-style="italic" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color" fo:font-weight="bold" officeooo:rsid="0005ce88" officeooo:paragraph-rsid="0005ce88" style:font-style-asian="italic" style:font-weight-asian="bold" style:font-style-complex="italic" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="P30" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:paragraph-rsid="0005ce88"/>
  </style:style>
  <style:style style:name="P31" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="000ab958" officeooo:paragraph-rsid="000ab958"/>
  </style:style>
  <style:style style:name="P32" style:family="paragraph" style:parent-style-name="Text_20_body">
   <style:text-properties officeooo:rsid="0007c9b3" officeooo:paragraph-rsid="0007c9b3"/>
  </style:style>
  <style:style style:name="P33" style:family="paragraph" style:parent-style-name="Heading_20_3">
   <style:text-properties officeooo:rsid="0007c9b3"/>
  </style:style>
  <style:style style:name="P34" style:family="paragraph" style:parent-style-name="Heading_20_2">
   <style:text-properties officeooo:paragraph-rsid="000ab958"/>
  </style:style>
  <style:style style:name="P35" style:family="paragraph" style:parent-style-name="Heading_20_2">
   <style:paragraph-properties fo:break-before="page"/>
  </style:style>
  <style:style style:name="P36" style:family="paragraph" style:parent-style-name="Heading_20_2">
   <style:paragraph-properties fo:break-before="page"/>
   <style:text-properties officeooo:rsid="000590ec" officeooo:paragraph-rsid="000590ec"/>
  </style:style>
  <style:style style:name="P37" style:family="paragraph" style:parent-style-name="Contents_20_2">
   <style:paragraph-properties>
    <style:tab-stops>
     <style:tab-stop style:position="6.7283in" style:type="right" style:leader-style="dotted" style:leader-text="."/>
    </style:tab-stops>
   </style:paragraph-properties>
  </style:style>
  <style:style style:name="P38" style:family="paragraph" style:parent-style-name="Contents_20_3">
   <style:paragraph-properties>
    <style:tab-stops>
     <style:tab-stop style:position="6.5319in" style:type="right" style:leader-style="dotted" style:leader-text="."/>
    </style:tab-stops>
   </style:paragraph-properties>
  </style:style>
  <style:style style:name="T1" style:family="text">
   <style:text-properties officeooo:rsid="00054130"/>
  </style:style>
  <style:style style:name="T2" style:family="text">
   <style:text-properties officeooo:rsid="000590ec"/>
  </style:style>
  <style:style style:name="T3" style:family="text">
   <style:text-properties fo:font-weight="bold" style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="T4" style:family="text">
   <style:text-properties fo:font-weight="bold" officeooo:rsid="000ab958" style:font-weight-asian="bold" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="T5" style:family="text">
   <style:text-properties fo:font-style="italic" style:text-underline-style="solid" style:text-underline-width="auto" style:text-underline-color="font-color" fo:font-weight="bold" style:font-style-asian="italic" style:font-weight-asian="bold" style:font-style-complex="italic" style:font-weight-complex="bold"/>
  </style:style>
  <style:style style:name="T6" style:family="text">
   <style:text-properties officeooo:rsid="0005ce88"/>
  </style:style>
  <style:style style:name="T7" style:family="text">
   <style:text-properties officeooo:rsid="0007c9b3"/>
  </style:style>
  <style:style style:name="T8" style:family="text">
   <style:text-properties officeooo:rsid="00098d4f"/>
  </style:style>
  <style:style style:name="T9" style:family="text">
   <style:text-properties officeooo:rsid="000a23ed"/>
  </style:style>
  <style:style style:name="T10" style:family="text">
   <style:text-properties officeooo:rsid="000ab958"/>
  </style:style>
  <style:style style:name="Sect1" style:family="section">
   <style:section-properties style:editable="false">
    <style:columns fo:column-count="1" fo:column-gap="0in"/>
   </style:section-properties>
  </style:style>
  <text:list-style style:name="L1">
   <text:list-level-style-bullet text:level="1" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.5in" fo:text-indent="-0.25in" fo:margin-left="0.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="2" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.75in" fo:text-indent="-0.25in" fo:margin-left="0.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="3" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1in" fo:text-indent="-0.25in" fo:margin-left="1in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="4" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.25in" fo:text-indent="-0.25in" fo:margin-left="1.25in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="5" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.5in" fo:text-indent="-0.25in" fo:margin-left="1.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="6" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.75in" fo:text-indent="-0.25in" fo:margin-left="1.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="7" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2in" fo:text-indent="-0.25in" fo:margin-left="2in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="8" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.25in" fo:text-indent="-0.25in" fo:margin-left="2.25in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="9" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.5in" fo:text-indent="-0.25in" fo:margin-left="2.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="10" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.75in" fo:text-indent="-0.25in" fo:margin-left="2.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
  </text:list-style>
  <text:list-style style:name="L2">
   <text:list-level-style-bullet text:level="1" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.5in" fo:text-indent="-0.25in" fo:margin-left="0.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="2" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.75in" fo:text-indent="-0.25in" fo:margin-left="0.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="3" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1in" fo:text-indent="-0.25in" fo:margin-left="1in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="4" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.25in" fo:text-indent="-0.25in" fo:margin-left="1.25in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="5" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.5in" fo:text-indent="-0.25in" fo:margin-left="1.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="6" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.75in" fo:text-indent="-0.25in" fo:margin-left="1.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="7" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2in" fo:text-indent="-0.25in" fo:margin-left="2in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="8" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.25in" fo:text-indent="-0.25in" fo:margin-left="2.25in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="9" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.5in" fo:text-indent="-0.25in" fo:margin-left="2.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="10" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.75in" fo:text-indent="-0.25in" fo:margin-left="2.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
  </text:list-style>
  <text:list-style style:name="L3">
   <text:list-level-style-bullet text:level="1" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.5in" fo:text-indent="-0.25in" fo:margin-left="0.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="2" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="0.75in" fo:text-indent="-0.25in" fo:margin-left="0.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="3" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1in" fo:text-indent="-0.25in" fo:margin-left="1in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="4" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.25in" fo:text-indent="-0.25in" fo:margin-left="1.25in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="5" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.5in" fo:text-indent="-0.25in" fo:margin-left="1.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="6" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="1.75in" fo:text-indent="-0.25in" fo:margin-left="1.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="7" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2in" fo:text-indent="-0.25in" fo:margin-left="2in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="8" text:style-name="Bullet_20_Symbols" text:bullet-char="◦">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.25in" fo:text-indent="-0.25in" fo:margin-left="2.25in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="9" text:style-name="Bullet_20_Symbols" text:bullet-char="▪">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.5in" fo:text-indent="-0.25in" fo:margin-left="2.5in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
   <text:list-level-style-bullet text:level="10" text:style-name="Bullet_20_Symbols" text:bullet-char="•">
    <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
     <style:list-level-label-alignment text:label-followed-by="listtab" text:list-tab-stop-position="2.75in" fo:text-indent="-0.25in" fo:margin-left="2.75in"/>
    </style:list-level-properties>
   </text:list-level-style-bullet>
  </text:list-style>
  <style:page-layout style:name="pm1">
   <style:page-layout-properties fo:page-width="8.5in" fo:page-height="11in" style:num-format="1" style:print-orientation="portrait" fo:margin-top="0.7874in" fo:margin-bottom="0.7874in" fo:margin-left="0.7874in" fo:margin-right="0.7874in" style:writing-mode="lr-tb" style:footnote-max-height="0in">
    <style:footnote-sep style:width="0.0071in" style:distance-before-sep="0.0398in" style:distance-after-sep="0.0398in" style:line-style="none" style:adjustment="left" style:rel-width="25%" style:color="#000000"/>
   </style:page-layout-properties>
   <style:header-style/>
   <style:footer-style>
    <style:header-footer-properties fo:min-height="0in" fo:margin-left="0in" fo:margin-right="0in" fo:margin-top="0.1965in"/>
   </style:footer-style>
  </style:page-layout>
 </office:automatic-styles>
 <office:master-styles>
  <style:master-page style:name="Standard" style:page-layout-name="pm1">
   <style:footer>
    <table:table table:name="Table1" table:style-name="Table1">
     <table:table-column table:style-name="Table1.A"/>
     <table:table-column table:style-name="Table1.B" table:number-columns-repeated="3"/>
     <table:table-row>
      <table:table-cell table:style-name="Table1.A1" office:value-type="string">
       <text:p text:style-name="P22">AppSec Team</text:p>
      </table:table-cell>
      <table:table-cell table:style-name="Table1.A1" office:value-type="string">
       <text:p text:style-name="P23">Confidential</text:p>
      </table:table-cell>
      <table:table-cell table:style-name="Table1.A1" office:value-type="string">
       <text:p text:style-name="P21"/>
      </table:table-cell>
      <table:table-cell table:style-name="Table1.A1" office:value-type="string">
       <text:p text:style-name="P1"><text:span text:style-name="T1"><text:s/></text:span><text:page-number text:select-page="current">5</text:page-number> <text:span text:style-name="T1">of </text:span><text:span text:style-name="T1"><text:page-count>5</text:page-count></text:span><text:span text:style-name="T1"> </text:span></text:p>
      </table:table-cell>
     </table:table-row>
    </table:table>
    <text:p text:style-name="P1"/>
   </style:footer>
  </style:master-page>
 </office:master-styles>
 <office:body>
  <office:text text:use-soft-page-breaks="true">
   <text:sequence-decls>
    <text:sequence-decl text:display-outline-level="0" text:name="Illustration"/>
    <text:sequence-decl text:display-outline-level="0" text:name="Table"/>
    <text:sequence-decl text:display-outline-level="0" text:name="Text"/>
    <text:sequence-decl text:display-outline-level="0" text:name="Drawing"/>
   </text:sequence-decls>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="Standard"/>
   <text:p text:style-name="P8">Application Security <text:line-break/><text:span text:style-name="T8">Vulnerability Status</text:span> </text:p>
   <text:p text:style-name="P8">of <text:span text:style-name="T2">{{.Product}}</text:span></text:p>
   <text:p text:style-name="P4"/>
   <text:p text:style-name="P5"/>
   <text:p text:style-name="P7"><text:span text:style-name="T8">as of</text:span> {{.Month}} {{.Day}}, {{.YYYY}}</text:p>
   <text:p text:style-name="P7"><text:span text:style-name="T8">based on the efforts of</text:span> the<text:span text:style-name="T1"> AppSec Team</text:span></text:p>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"><text:soft-page-break/></text:p>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:table-of-content text:style-name="Sect1" text:protected="true" text:name="Table of Contents1">
    <text:table-of-content-source text:outline-level="10">
     <text:index-title-template text:style-name="Contents_20_Heading">Table of Contents</text:index-title-template>
     <text:table-of-content-entry-template text:outline-level="1" text:style-name="Contents_20_1">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="2" text:style-name="Contents_20_2">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="3" text:style-name="Contents_20_3">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="4" text:style-name="Contents_20_4">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="5" text:style-name="Contents_20_5">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="6" text:style-name="Contents_20_6">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="7" text:style-name="Contents_20_7">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="8" text:style-name="Contents_20_8">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="9" text:style-name="Contents_20_9">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
     <text:table-of-content-entry-template text:outline-level="10" text:style-name="Contents_20_10">
      <text:index-entry-link-start text:style-name="Index_20_Link"/>
      <text:index-entry-chapter/>
      <text:index-entry-text/>
      <text:index-entry-tab-stop style:type="right" style:leader-char="."/>
      <text:index-entry-page-number/>
      <text:index-entry-link-end/>
     </text:table-of-content-entry-template>
    </text:table-of-content-source>
    <text:index-body>
     <text:index-title text:style-name="Sect1" text:name="Table of Contents1_Head">
      <text:p text:style-name="Contents_20_Heading">Table of Contents</text:p>
     </text:index-title>
     <text:p text:style-name="P37"><text:a xlink:type="simple" xlink:href="#__RefHeading__849_527103283" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Scope<text:tab/>3</text:a></text:p>
     <text:p text:style-name="P37"><text:a xlink:type="simple" xlink:href="#__RefHeading__855_527103283" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Executive Summary<text:tab/>3</text:a></text:p>
     <text:p text:style-name="P37"><text:a xlink:type="simple" xlink:href="#__RefHeading__857_527103283" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Recommendations and observations<text:tab/>3</text:a></text:p>
     <text:p text:style-name="P37"><text:a xlink:type="simple" xlink:href="#__RefHeading___Toc669_1969340580" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Details of the Critical risk findings<text:tab/>4</text:a></text:p>
     <text:p text:style-name="P37"><text:a xlink:type="simple" xlink:href="#__RefHeading___Toc671_1969340580" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Detailed Findings<text:tab/>5</text:a></text:p>
     <text:p text:style-name="P38"><text:a xlink:type="simple" xlink:href="#__RefHeading___Toc673_1969340580" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Finding A3S58-1: Cross-site scripting (reflected)<text:tab/>5</text:a></text:p>
     <text:p text:style-name="P37"><text:a xlink:type="simple" xlink:href="#__RefHeading___Toc677_1969340580" text:style-name="Index_20_Link" text:visited-style-name="Index_20_Link">Appendix<text:tab/>5</text:a></text:p>
    </text:index-body>
   </text:table-of-content>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:p text:style-name="P3"/>
   <text:h text:style-name="P10" text:outline-level="2"><text:bookmark-start text:name="__RefHeading__849_527103283"/>Scope<text:bookmark-end text:name="__RefHeading__849_527103283"/></text:h>
   <text:p text:style-name="P11">The scope of this assessment was {{.Product}} and included <text:span text:style-name="T8">any vulnerability discovered by the AppSec Team during any prior assessments of {{.Product}}. <text:s/>The vulnerability status is a combination of static analysis (source code), dynamic analysis (running code) and manual testing efforts. <text:s/>Any vulnerabilities discovered during the above activities have been summarized in this report as of {{.Month}} {{.Day}}, {{.YYYY}}.</text:span></text:p>
   <text:h text:style-name="P34" text:outline-level="2"><text:bookmark-start text:name="__RefHeading__855_527103283"/>Executive Summary<text:bookmark-end text:name="__RefHeading__855_527103283"/></text:h>
   <text:p text:style-name="P30"><text:span text:style-name="T6">Prior testing has uncovered {{.TotFind}} total issues which have been reported to the {{.Product}} team. <text:s/>The Application Security team has worked with the {{.Product}} team to mitigate findings as quickly as possible especially any critical and high findings. <text:s/>Overall, the breakdown of the findings for {{.Product}} <text:s/>issues:</text:span></text:p>
   <text:list xml:id="list5664825623883774456" text:style-name="L1">
    <text:list-item>
     <text:p text:style-name="P26">{{.NumCrit}} Critical risk findings </text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P26">{{.NumHigh}} High risk findings</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P26">{{.NumMed}} Medium risk findings</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P26">{{.NumLow}} Low risk findings</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P26">{{.NumInfo}} Informational findings</text:p>
    </text:list-item>
   </text:list>
   <text:p text:style-name="P13">*CHANGE AS NEEDED* All the findings discovered during testing have been added to BUG TRACKER for the {{.Product}} project. <text:s/>Of the {{.TotFind}} total issues, *X* were application specific vulnerabilities while the remaining *Y* were infrastructure. <text:s/>To date, all the critical risk findings have been mitigated. <text:s/>Additional details on the {{.NumCrit}} critical issues follow after the recommendations below.</text:p>
   <text:h text:style-name="Heading_20_2" text:outline-level="2"><text:bookmark-start text:name="__RefHeading__857_527103283"/>Recommendations and observations<text:bookmark-end text:name="__RefHeading__857_527103283"/></text:h>
   <text:list xml:id="list1636808628893577882" text:style-name="L3">
    <text:list-item>
     <text:p text:style-name="P29">CHANGE BELOW AS NEEDED</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P27">All the High risk findings need a remediation plan within 7 days</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P27">All the Medium and lower risk findings need a remediation plan within 14 days</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P27">All the Low risk findings need a remediation plan within 30 days</text:p>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P27">Other testing observations</text:p>
     <text:list>
      <text:list-item>
       <text:p text:style-name="P27">Possibly with sub-points</text:p>
      </text:list-item>
      <text:list-item>
       <text:p text:style-name="P27">Maybe two</text:p>
      </text:list-item>
     </text:list>
    </text:list-item>
    <text:list-item>
     <text:p text:style-name="P27">The last source code scan of {{.Product}} was DATE HERE, over TIME ago.</text:p>
     <text:list>
      <text:list-item>
       <text:p text:style-name="P27"><text:soft-page-break/>A source code scan of the {{.Product}} will need to be completed within <text:span text:style-name="T5">X</text:span> days</text:p>
      </text:list-item>
      <text:list-item>
       <text:p text:style-name="P27">Code scans of the source should be conducted regularly - ideally as part of regular builds or continuous integration</text:p>
      </text:list-item>
     </text:list>
    </text:list-item>
   </text:list>
   <text:p text:style-name="P13"/>
   <text:h text:style-name="Heading_20_2" text:outline-level="2"><text:bookmark-start text:name="__RefHeading___Toc669_1969340580"/>Details of the Critical risk findings <text:bookmark-end text:name="__RefHeading___Toc669_1969340580"/></text:h>
   <text:p text:style-name="P14">[Optional section – remove if not critical risk issues were found]</text:p>
   <text:p text:style-name="P13">WRITE A BRIEF AND HIGH LEVEL DESCRIPTION OF THE CRITICAL FINDINGS AND THEIR IMPACT ON <text:span text:style-name="T10">THE COMPANY</text:span> HERE.</text:p>
   <text:p text:style-name="P13"/>
   <text:h text:style-name="P9" text:outline-level="2">Detailed Findings</text:h>
{{with .Finds}}{{range .}}
   <text:h text:style-name="Heading_20_3" text:outline-level="3">Finding {{.AppId}}{{.ScanId}}-{{.Id}}: {{.Title}}</text:h>
   <text:p text:style-name="P18"><text:line-break/><text:span text:style-name="T3">Severity: High</text:span></text:p>
   <text:p text:style-name="P15">Details</text:p>
   <text:p text:style-name="P18">{{.Path}}{{.AttString}}{{.AttReq}}{{.AttResp}}</text:p>
   <text:p text:style-name="P15">Description:</text:p>
   <text:p text:style-name="P18">ADD DESCRIPTION HERE</text:p>
   <text:p text:style-name="P15">Impact:</text:p>
   <text:p text:style-name="P18">ADD IMPACT OF FINDINGS HERE</text:p>
   <text:p text:style-name="P15">References:</text:p>
   <text:p text:style-name="P18"><text:a xlink:type="simple" xlink:href="http://cwe.mitre.org/data/definitions/611.html" text:style-name="Internet_20_link" text:visited-style-name="Visited_20_Internet_20_Link">CWE-[[FIX-ME]]: [[Plus the title that goes here and the HTML link - sorry]]</text:a></text:p>
   <text:h text:style-name="P33" text:outline-level="3"/>
{{end}}{{end}}
   <text:h text:style-name="Heading_20_2" text:outline-level="2">Appendix</text:h>
   <text:p text:style-name="P31">Add stuff here or remove if not needed.</text:p>
   <text:p text:style-name="P19"/>
  </office:text>
 </office:body>
</office:document>
`
